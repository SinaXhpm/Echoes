using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Reverse DNS (PTR) names for the MTR table: looked up in the background, a few at a time, each given a few seconds,
/// and cached for the session — a hop's name is asked for once, however many rounds and runs it appears in. A lookup
/// that failed for a transient reason (timeout, resolver down) is forgotten after a minute so a later run retries it;
/// "no such name" stays cached.
/// </summary>
public static class MtrReverseDns
{
    private static readonly ConcurrentDictionary<IPAddress, Task<string?>> Cache = new();
    private static readonly SemaphoreSlim Slots = new(4);
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);

    /// <summary>The longest DNS name (RFC 1035); a PTR "name" past it is not a name.</summary>
    public const int MaxNameLength = 253;

    /// <summary>The name if its lookup has already finished, else null (a lookup is started).</summary>
    public static string? Peek(IPAddress address)
    {
        var task = LookupAsync(address);
        return task.IsCompletedSuccessfully ? task.Result : null;
    }

    /// <summary>The PTR name of <paramref name="address"/> (no trailing dot), or null when there is none or it didn't
    /// come in time. Never throws.</summary>
    public static Task<string?> LookupAsync(IPAddress address) => Cache.GetOrAdd(address, Lookup);

    private static async Task<string?> Lookup(IPAddress address)
    {
        bool transient = false;
        await Slots.WaitAsync().ConfigureAwait(false);
        Task<IPHostEntry> lookup;
        try { lookup = Dns.GetHostEntryAsync(address); }
        catch (Exception)
        {
            Slots.Release();
            Forget(address);
            return null;
        }
        // The slot is freed when the OS call really ends, not at our deadline: getnameinfo has no async form, so each
        // lookup holds a pool thread until the resolver gives up. Freed at the deadline, a silent resolver let a new
        // batch of blocked threads start every 3 s — +13 pool threads for one 30-hop path (round-5 harness, WSL).
        _ = lookup.ContinueWith(static (t, s) => { _ = t.Exception; ((SemaphoreSlim)s!).Release(); }, Slots,
                                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        try
        {
            // The resolver keeps going after a timeout (the OS call can't be cancelled); only the wait ends.
            var entry = await lookup.WaitAsync(Timeout).ConfigureAwait(false);
            string? name = Clean(entry.HostName?.Trim().TrimEnd('.'));
            // Some platforms hand the address back as the "name" when there is no PTR record.
            return name is null || IPAddress.TryParse(name, out _) ? null : name;
        }
        catch (SocketException e) when (e.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData)
        {
            return null;
        }
        catch (Exception)
        {
            transient = true;
            return null;
        }
        finally
        {
            if (transient) Forget(address);
        }
    }

    // A transient failure: drop the cached answer after a minute, so a later run asks again.
    private static void Forget(IPAddress address)
        => _ = Task.Delay(TimeSpan.FromMinutes(1)).ContinueWith(_ => Cache.TryRemove(address, out var _), TaskScheduler.Default);

    /// <summary>
    /// A PTR name as it may be shown: whoever controls the address space writes these, so control characters (a line
    /// break in the copied report), bidi overrides (text that reads backwards) and invisible format characters become
    /// '?', and anything past a DNS name's 253 characters is cut. Null for nothing left.
    /// </summary>
    public static string? Clean(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        int n = Math.Min(name.Length, MaxNameLength);
        if (n < name.Length && char.IsHighSurrogate(name[n - 1])) n--;   // don't cut a pair in half
        var sb = new StringBuilder(n);
        for (int i = 0; i < n; i++)
        {
            char c = name[i];
            // A surrogate pair is judged as the one character it encodes (U+E0000 tags are invisible format characters).
            bool pair = char.IsHighSurrogate(c) && i + 1 < n && char.IsLowSurrogate(name[i + 1]);
            var category = pair ? CharUnicodeInfo.GetUnicodeCategory(char.ConvertToUtf32(c, name[i + 1]))
                         : char.IsSurrogate(c) ? UnicodeCategory.Surrogate   // an unpaired half
                         : CharUnicodeInfo.GetUnicodeCategory(c);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator)
            {
                sb.Append('?');
                if (pair) i++;
                continue;
            }
            sb.Append(c);
            if (pair) sb.Append(name[++i]);
        }
        string s = sb.ToString().Trim();
        return s.Length == 0 ? null : s;
    }
}
