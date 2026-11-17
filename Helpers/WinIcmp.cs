using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Windows: an ICMP echo sent from a chosen interface (<c>ping -S</c>). The managed <see cref="Ping"/> always lets the
/// system pick the source, so this calls what it wraps, with the source address filled in: IcmpSendEcho2Ex (IPv4) and
/// Icmp6SendEcho2 (IPv6). Windows sends a packet only from the interface that owns its source address, so the address
/// chooses the interface. No privileges needed, like the managed class.
/// <para>Asynchronous the same way the managed class is: the call returns at once, an event is signalled when the
/// reply (or the timeout) is in, and a pool wait reads it. Results come back in <see cref="IcmpPinger"/>'s shape with
/// the managed path's error names (an <see cref="IPStatus"/> name), so every caller reads them as before.</para>
/// </summary>
internal static class WinIcmp
{
    private const int ErrorIoPending = 997;
    private const int IpStatusBase = 11000;
    private const byte DontFragmentFlag = 2;

    /// <summary>One echo to <paramref name="addr"/> from <paramref name="via"/>. Never throws except
    /// <see cref="OperationCanceledException"/>.</summary>
    public static Task<IcmpPinger.PingResult> SendAsync(IPAddress addr, NetIface via, int timeoutMs, IcmpProbeOptions o, bool custom,
                                                        byte[] payload, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        bool v6 = addr.AddressFamily == AddressFamily.InterNetworkV6;

        // which of the asked options go out (the managed path's rules: a classic probe with a TTL sets DF, as tracert does)
        var applied = IcmpApplied.Size;
        string? note = null;
        bool df = custom ? o.DontFragment : o.Ttl > 0;
        if (custom && o.Ttl > 0) applied |= IcmpApplied.Ttl;
        if (custom && o.DontFragment)
        {
            if (v6) note = IcmpPinger.Df6Note;
            else applied |= IcmpApplied.DontFragment;
        }

        if (via.SourceFor(addr) is not { } source) return Task.FromResult(IcmpPinger.Unsent(via.Missing(addr)!));

        var options = new IpOptionInformation
        {
            Ttl = (byte)(o.Ttl > 0 ? o.Ttl : 128),   // what Windows sends by default
            Flags = df && !v6 ? DontFragmentFlag : (byte)0,
        };

        // One block for the request and the reply: the system writes the reply while this method has long returned, so
        // it is freed only by the completion (which always comes: the timeout signals the event too).
        int replySize = Math.Max(1024, payload.Length + 512);
        var state = new Pending
        {
            V6 = v6,
            Applied = applied,
            Note = note,
            Target = addr,
            Memory = Marshal.AllocHGlobal(payload.Length + replySize),
            Event = new ManualResetEvent(false),
            Done = new TaskCompletionSource<IcmpPinger.PingResult>(TaskCreationOptions.RunContinuationsAsynchronously),
        };
        IntPtr request = state.Memory, reply = state.Memory + payload.Length;
        state.Reply = reply;
        Marshal.Copy(payload, 0, request, payload.Length);

        try
        {
            state.Handle = v6 ? Icmp6CreateFile() : IcmpCreateFile();
            if (state.Handle == IntPtr.Zero || state.Handle == new IntPtr(-1))
            {
                int code = Marshal.GetLastWin32Error();
                state.Handle = IntPtr.Zero;
                state.Free();
                return Task.FromResult(IcmpPinger.Unsent(Why(code, via)));
            }

            state.Wait = ThreadPool.RegisterWaitForSingleObject(state.Event, static (s, _) => ((Pending)s!).Complete(), state,
                                                                Timeout.Infinite, executeOnlyOnce: true);
            state.Clock = Stopwatch.StartNew();
            IntPtr signal = state.Event.SafeWaitHandle.DangerousGetHandle();
            uint sent = v6
                ? Icmp6SendEcho2(state.Handle, signal, IntPtr.Zero, IntPtr.Zero, SockAddr6(source), SockAddr6(addr),
                                 request, (ushort)payload.Length, ref options, reply, (uint)replySize, (uint)timeoutMs)
                : IcmpSendEcho2Ex(state.Handle, signal, IntPtr.Zero, IntPtr.Zero, V4(source), V4(addr),
                                  request, (ushort)payload.Length, ref options, reply, (uint)replySize, (uint)timeoutMs);
            int error = sent == 0 ? Marshal.GetLastWin32Error() : 0;
            if (sent == 0 && error != ErrorIoPending)
            {
                // refused before anything was queued (no such source address any more, no route from it): no event comes
                state.Free();
                // an IP status of its own (a packet over the link MTU with DF set: PacketTooBig) is a probe's answer;
                // anything else means it couldn't be sent from this interface
                return Task.FromResult(error >= IpStatusBase
                    ? new IcmpPinger.PingResult(false, 0, null, -1, ((IPStatus)error).ToString(), false, PingMethod.Icmp, applied, 0, note)
                    : IcmpPinger.Unsent(Why(error, via)));
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            state.Free();
            return Task.FromResult(IcmpPinger.Unsent("choosing the interface for ICMP isn't available on this Windows: " + ex.Message));
        }

        // Stopped: the caller gets on at once; the request is left to end by itself (its timeout), which frees it.
        return state.Done.Task.WaitAsync(token);
    }

    // Why Windows wouldn't send from this interface, in a few words (its own messages run to two sentences of advice).
    private static string Why(int error, NetIface via) => error switch
    {
        1231 => $"no route to it from {via.Name}",                    // ERROR_NETWORK_UNREACHABLE
        1232 => $"it can't be reached from {via.Name}",               // ERROR_HOST_UNREACHABLE
        87 or 1214 => $"{via.Name} has lost its address (disconnected?)",   // ERROR_INVALID_PARAMETER / ERROR_INVALID_NETNAME
        _ => $"can't send from {via.Name}: {FirstSentence(new Win32Exception(error).Message)}",
    };

    private static string FirstSentence(string message)
    {
        int end = message.IndexOf(". ", StringComparison.Ordinal);
        return (end > 0 ? message[..end] : message.TrimEnd('.')).Trim();
    }

    private sealed class Pending
    {
        public bool V6;
        public IcmpApplied Applied;
        public string? Note;
        public IPAddress Target = IPAddress.None;
        public IntPtr Memory, Reply, Handle;
        public ManualResetEvent Event = null!;
        public RegisteredWaitHandle? Wait;
        public Stopwatch Clock = null!;
        public TaskCompletionSource<IcmpPinger.PingResult> Done = null!;
        private int _freed;

        // The event was signalled: the reply (or the timeout's status) is in the buffer.
        public void Complete()
        {
            long waited = Clock.ElapsedMilliseconds;
            IcmpPinger.PingResult result;
            try
            {
                uint status, rtt;
                IPAddress from;
                int ttl = -1;
                if (V6)
                {
                    // ICMPV6_ECHO_REPLY: { port u16, flowinfo u32, address 16 bytes, scope u32 } packed, then status, RTT
                    var address = new byte[16];
                    Marshal.Copy(Reply + 6, address, 0, 16);
                    uint scope = (uint)Marshal.ReadInt32(Reply, 22);
                    from = new IPAddress(address, scope);
                    status = (uint)Marshal.ReadInt32(Reply, 28);
                    rtt = (uint)Marshal.ReadInt32(Reply, 32);
                }
                else
                {
                    // ICMP_ECHO_REPLY: address, status, RTT, data size u16, reserved u16, data pointer, then the options
                    from = new IPAddress((long)(uint)Marshal.ReadInt32(Reply, 0));
                    status = (uint)Marshal.ReadInt32(Reply, 4);
                    rtt = (uint)Marshal.ReadInt32(Reply, 8);
                    if (status == 0) ttl = Marshal.ReadByte(Reply, 16 + IntPtr.Size);
                }
                bool ok = status == 0;
                // Windows fills the round trip only for an echo reply: the other answers (a router's "TTL expired") are
                // timed here, as the managed path's callers do.
                result = new IcmpPinger.PingResult(ok, ok ? rtt : waited, from, ttl, ok ? null : ((IPStatus)status).ToString(),
                                                   false, PingMethod.Icmp, Applied, 0, Note);
            }
            catch (Exception ex)
            {
                result = new IcmpPinger.PingResult(false, waited, null, -1, ex.Message, false, PingMethod.Icmp, Applied, 0, Note);
            }
            Free();
            Done.TrySetResult(result);
        }

        public void Free()
        {
            if (Interlocked.Exchange(ref _freed, 1) != 0) return;
            if (Handle != IntPtr.Zero) IcmpCloseHandle(Handle);
            Marshal.FreeHGlobal(Memory);
            Wait?.Unregister(null);
            Event.Dispose();
        }
    }

    private static uint V4(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return BitConverter.ToUInt32(b, 0);   // the bytes as they are on the wire (network order), like in_addr
    }

    // SOCKADDR_IN6: family, port, flow info, the address, the scope id (a link-local address's interface)
    private static byte[] SockAddr6(IPAddress a)
    {
        var s = new byte[28];
        s[0] = 23;   // AF_INET6
        a.GetAddressBytes().CopyTo(s, 8);
        BitConverter.GetBytes((uint)a.ScopeId).CopyTo(s, 24);
        return s;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IpOptionInformation
    {
        public byte Ttl, Tos, Flags, OptionsSize;
        public IntPtr OptionsData;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern IntPtr IcmpCreateFile();

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern IntPtr Icmp6CreateFile();

    [DllImport("iphlpapi.dll")]
    private static extern int IcmpCloseHandle(IntPtr handle);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint IcmpSendEcho2Ex(IntPtr handle, IntPtr signal, IntPtr apcRoutine, IntPtr apcContext,
                                               uint source, uint destination, IntPtr request, ushort requestSize,
                                               ref IpOptionInformation options, IntPtr reply, uint replySize, uint timeout);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint Icmp6SendEcho2(IntPtr handle, IntPtr signal, IntPtr apcRoutine, IntPtr apcContext,
                                              byte[] source, byte[] destination, IntPtr request, ushort requestSize,
                                              ref IpOptionInformation options, IntPtr reply, uint replySize, uint timeout);
}
