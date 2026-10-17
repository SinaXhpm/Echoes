using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Reverse DNS (PTR) names for the hosts a scan finds up, the way nmap names them — in the background, so the port
/// scan never waits on DNS. Bounded: the OS resolver blocks a pool thread per lookup (getnameinfo has no async form),
/// so at most <c>parallel</c> lookups run at once — counting ones we gave up on, whose thread is still busy — and each
/// gets a deadline. Lookups outlive the scan that queued them (a /24's names can take a minute to trickle in); one
/// lookup per address for the scanner's lifetime (repeat passes reuse the name).
/// </summary>
public sealed class ScanNames
{
    private const int DeadlineMs = 3000;

    private readonly SemaphoreSlim _slots;
    private readonly Action<ScanHost> _resolved;
    private readonly ConcurrentDictionary<string, Task> _lookups = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _drop = new();
    private int _pending;

    /// <param name="resolved">Called (from a worker thread) when a host gets a name.</param>
    public ScanNames(int parallel, Action<ScanHost> resolved)
    {
        _slots = new SemaphoreSlim(Math.Max(1, parallel));
        _resolved = resolved;
    }

    /// <summary>Lookups queued and not finished yet.</summary>
    public bool Busy => Volatile.Read(ref _pending) > 0;

    /// <summary>Start a lookup for this host unless one ran already. Never throws.</summary>
    public void Queue(ScanHost host)
    {
        if (host.ReverseName is not null) return;
        _lookups.GetOrAdd(host.Ip, _ =>
        {
            Interlocked.Increment(ref _pending);
            return LookupAsync(host);
        });
    }

    /// <summary>Wait for the outstanding lookups, at most <paramref name="grace"/>; later names still arrive.</summary>
    public async Task WaitAsync(TimeSpan grace, CancellationToken ct)
    {
        try { await Task.WhenAll(_lookups.Values).WaitAsync(grace, ct).ConfigureAwait(false); }
        catch { /* timed out / stopped: the rest land later */ }
    }

    /// <summary>
    /// The results these names were for are gone (a new scan started): drop the lookups still waiting for a slot. Those
    /// already with the OS (at most <c>parallel</c>) end on their own. Without this a sweep's queue ran on, a few at a
    /// time, long after its scan — 65,536 lookups for a /16 that a transparent proxy made all "up".
    /// </summary>
    public void Cancel()
    {
        try { _drop.Cancel(); } catch (ObjectDisposedException) { }
    }

    private async Task LookupAsync(ScanHost host)
    {
        try
        {
            await _slots.WaitAsync(_drop.Token).ConfigureAwait(false);
            Task<IPHostEntry> lookup;
            try { lookup = Dns.GetHostEntryAsync(host.Address); }
            catch { _slots.Release(); return; }
            // The slot is freed when the OS call really ends, not at our deadline: its pool thread stays blocked until then.
            _ = lookup.ContinueWith(static (t, s) => { _ = t.Exception; ((SemaphoreSlim)s!).Release(); }, _slots,
                                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            var entry = await lookup.WaitAsync(TimeSpan.FromMilliseconds(DeadlineMs)).ConfigureAwait(false);
            string name = entry.HostName?.TrimEnd('.') ?? "";
            // No PTR record: some resolvers hand back the address itself.
            if (name.Length == 0 || IPAddress.TryParse(name, out _)) return;
            host.ReverseName = ServiceScanner.Sanitize(name);
            _resolved(host);
        }
        catch { /* no PTR, or past the deadline */ }
        finally { Interlocked.Decrement(ref _pending); }
    }
}
