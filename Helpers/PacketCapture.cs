using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>A frame as the capture engine hands it over (on its own thread).</summary>
public readonly record struct CapturedFrame(DateTime TimeUtc, int WireLength, byte[] Data, LinkKind Link);

/// <summary>Live capture can't start; <see cref="Exception.Message"/> says why and what to do, in plain words.</summary>
public sealed class CaptureException(string message) : Exception(message);

/// <summary>
/// A live packet capture on one interface. What does the capturing depends on the system, and nothing is bundled:
/// <list type="bullet">
/// <item>Windows with Npcap installed (it comes with Wireshark): Npcap. Whole Ethernet frames, both directions, the
/// loopback adapter, and no administrator rights (unless Npcap was installed "for administrators only").</item>
/// <item>Windows without Npcap, Echoes started as administrator: a raw socket (SIO_RCVALL). IPv4 packets from the
/// IP header on (no Ethernet header, no ARP, no IPv6) of the chosen interface's address.</item>
/// <item>Linux: a packet socket (AF_PACKET), which needs root or CAP_NET_RAW.</item>
/// <item>macOS: the system's libpcap, which needs access to /dev/bpf* (root, or Wireshark's ChmodBPF); never inside
/// the Mac App Store sandbox.</item>
/// </list>
/// Android and iOS give an app no way to see other apps' packets. <see cref="Start"/> returns the running capture or
/// throws a <see cref="CaptureException"/> that says which of these is missing. Frames arrive on the capture's own
/// thread; <see cref="Stop"/> ends it (the end callback follows, with null).
/// </summary>
public abstract class PacketCapture
{
    /// <summary>The most a frame may hold (a jumbo frame, or a 64 KB packet before segmentation offload splits it).</summary>
    protected const int MaxFrame = 262144;

    private readonly Action<CapturedFrame> _onFrame;
    private readonly Action<string?> _onEnd;
    private int _ended;
    protected volatile bool Stopping;

    protected PacketCapture(Action<CapturedFrame> onFrame, Action<string?> onEnd)
    {
        _onFrame = onFrame;
        _onEnd = onEnd;
    }

    /// <summary>What captures, in a few words for the status line ("Npcap", "a raw socket (IPv4 only)").</summary>
    public abstract string Engine { get; }

    /// <summary>Packets the engine itself had to drop (its buffer was full); -1 where it doesn't say.</summary>
    public virtual long Dropped => -1;

    /// <summary>Asks the capture to end. Returns at once; the end callback follows from the capture's thread.</summary>
    public virtual void Stop() => Stopping = true;

    protected void Deliver(in CapturedFrame frame) => _onFrame(frame);

    /// <summary>Reports the end once: null when stopped, else what went wrong.</summary>
    protected void End(string? error)
    {
        if (Interlocked.Exchange(ref _ended, 1) == 0) _onEnd(Stopping ? null : error);
    }

    /// <summary>Whether this system can capture at all (the tool says so up front where it can't). Not in the Mac App
    /// Store build: its sandbox closes the capture devices to the app, whoever runs it.</summary>
    public static bool Supported
        => (OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()) && !AppInfo.IsMacSandbox;

    /// <summary>One line on what live capture needs here, for the page's hint.</summary>
    public static string Requirement
    {
        get
        {
            if (AppInfo.IsMacSandbox)
                return "The Mac App Store version can't capture live (its sandbox closes the capture devices): open a capture file instead.";
            if (OperatingSystem.IsWindows())
                return PcapNative.Available
                    ? "Captures with Npcap: whole frames, no administrator rights."
                    : "Live capture on Windows needs Npcap (free, it comes with Wireshark), or Echoes started as administrator (then IPv4 packets only).";
            if (OperatingSystem.IsLinux()) return "Live capture on Linux needs root or the CAP_NET_RAW capability.";
            if (OperatingSystem.IsMacOS()) return "Live capture on macOS needs access to /dev/bpf (root, or Wireshark's ChmodBPF).";
            return "This system gives apps no way to capture packets: open a capture file instead.";
        }
    }

    /// <summary>Starts capturing on <paramref name="iface"/>. <paramref name="promiscuous"/>: also frames addressed to
    /// other machines (where the engine and the network card allow it).</summary>
    public static PacketCapture Start(NetIface iface, bool promiscuous, Action<CapturedFrame> onFrame, Action<string?> onEnd)
    {
        if (AppInfo.IsMacSandbox) throw new CaptureException("The Mac App Store version can't capture live: its sandbox closes the capture devices.");
        if (OperatingSystem.IsWindows())
        {
            if (PcapNative.Available) return new PcapEngine(iface, promiscuous, onFrame, onEnd);
            if (Environment.IsPrivilegedProcess) return new RawSocketEngine(iface, promiscuous, onFrame, onEnd);
            throw new CaptureException("Capturing on Windows needs Npcap (free, from npcap.com; it also comes with Wireshark). "
                                       + "Without it, start Echoes as administrator to capture IPv4 packets.");
        }
        if (OperatingSystem.IsLinux()) return new LinuxEngine(iface, promiscuous, onFrame, onEnd);
        if (OperatingSystem.IsMacOS())
        {
            if (!PcapNative.Available) throw new CaptureException("macOS's capture library (libpcap) couldn't be loaded.");
            return new PcapEngine(iface, promiscuous, onFrame, onEnd);
        }
        throw new CaptureException("This system gives apps no way to capture packets.");
    }

    // ================================================================== Npcap / libpcap

    /// <summary>The pcap library's calls (Npcap's wpcap.dll on Windows, libpcap on macOS), loaded when first used and
    /// only from where the system keeps it.</summary>
    private static class PcapNative
    {
        // A name no system has: the resolver below is the only way to the library (Npcap lives in a folder of its own).
        private const string Lib = "echoes-pcap";
        private static readonly IntPtr s_handle;

        static PcapNative()
        {
            s_handle = Load();
            try { NativeLibrary.SetDllImportResolver(typeof(PcapNative).Assembly, Resolve); }
            catch (InvalidOperationException) { }   // set already
        }

        public static bool Available => s_handle != IntPtr.Zero;

        private static IntPtr Resolve(string name, Assembly assembly, DllImportSearchPath? path)
            => name == Lib ? s_handle : IntPtr.Zero;

        private static IntPtr Load()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    // Npcap's own folder under System32 (its default install); loaded by full path, so its Packet.dll
                    // comes from there too. Else a wpcap.dll in System32 itself (Npcap's WinPcap-compatible mode).
                    string npcap = Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll");
                    if (File.Exists(npcap) && NativeLibrary.TryLoad(npcap, out var own)) return own;
                    return NativeLibrary.TryLoad("wpcap.dll", typeof(PcapNative).Assembly, DllImportSearchPath.System32, out var shared)
                        ? shared : IntPtr.Zero;
                }
                if (OperatingSystem.IsMacOS())
                {
                    // by its full path only: a bare name would also be looked for in the folder Echoes was started from
                    foreach (string path in new[] { "/usr/lib/libpcap.dylib", "/usr/lib/libpcap.A.dylib" })
                        if (NativeLibrary.TryLoad(path, out var h)) return h;
                }
            }
            catch (Exception) { }
            return IntPtr.Zero;
        }

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_open_live(byte[] device, int snapLength, int promiscuous, int timeoutMs, byte[] error);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_next_ex(IntPtr handle, out IntPtr header, out IntPtr data);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_datalink(IntPtr handle);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_geterr(IntPtr handle);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_stats(IntPtr handle, out PcapStat stats);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_setbuff(IntPtr handle, int bytes);   // Npcap / WinPcap only

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_close(IntPtr handle);

        // struct pcap_stat: received, dropped by the buffer, dropped by the interface (Windows adds three more)
        [StructLayout(LayoutKind.Sequential)]
        public struct PcapStat
        {
            public uint Received, Dropped, InterfaceDropped, Captured, Sent, NetDropped;
        }
    }

    private sealed class PcapEngine : PacketCapture
    {
        private readonly IntPtr _handle;
        private readonly LinkKind _link;
        private long _dropped;

        public override string Engine => OperatingSystem.IsWindows() ? "Npcap" : "libpcap";
        public override long Dropped => Interlocked.Read(ref _dropped);

        public PcapEngine(NetIface iface, bool promiscuous, Action<CapturedFrame> onFrame, Action<string?> onEnd) : base(onFrame, onEnd)
        {
            // Npcap names a device after the adapter's GUID; libpcap after the interface
            string device = !OperatingSystem.IsWindows() ? iface.Name
                : iface.IsLoopback ? @"\Device\NPF_Loopback" : @"\Device\NPF_" + iface.Id;
            var error = new byte[512];
            // 100 ms: how long a read waits for packets, so how soon Stop is seen and a quiet line shows its packets
            _handle = PcapNative.pcap_open_live(Encoding.UTF8.GetBytes(device + "\0"), MaxFrame, promiscuous ? 1 : 0, 100, error);
            if (_handle == IntPtr.Zero)
            {
                string said = CString(error);
                throw new CaptureException(OperatingSystem.IsWindows()
                    ? $"Npcap couldn't open {iface.Name}: {said}"
                      + (iface.IsLoopback ? " (Npcap's loopback support may be off)" : string.Empty)
                    : said.Contains("ermission", StringComparison.Ordinal) || said.Contains("bpf", StringComparison.OrdinalIgnoreCase)
                        ? $"macOS didn't allow capturing on {iface.Name} ({said}). Capture devices are for root: start Echoes with sudo, or install Wireshark's ChmodBPF. The Mac App Store version can't capture."
                        : $"Couldn't capture on {iface.Name}: {said}");
            }
            _link = PcapFile.LinkOf(PcapNative.pcap_datalink(_handle));
            if (OperatingSystem.IsWindows())
            {
                try { PcapNative.pcap_setbuff(_handle, 8 * 1024 * 1024); }   // the default megabyte overflows during a download
                catch (EntryPointNotFoundException) { }
            }
            new Thread(Run) { IsBackground = true, Name = "Echoes capture" }.Start();
        }

        private void Run()
        {
            string? error = null;
            try
            {
                bool windows = OperatingSystem.IsWindows(), mac = OperatingSystem.IsMacOS();
                int polls = 0;
                while (!Stopping)
                {
                    int rc = PcapNative.pcap_next_ex(_handle, out IntPtr header, out IntPtr data);
                    if (rc == 1)
                    {
                        // struct pcap_pkthdr { struct timeval ts; u32 caplen; u32 len; }: a timeval is two 32-bit
                        // longs on Windows, 64-bit seconds elsewhere (then 64-bit microseconds on Linux, 32 on macOS)
                        long seconds, micros;
                        int at;
                        if (windows) { seconds = (uint)Marshal.ReadInt32(header, 0); micros = Marshal.ReadInt32(header, 4); at = 8; }
                        else { seconds = Marshal.ReadInt64(header, 0); micros = mac ? Marshal.ReadInt32(header, 8) : Marshal.ReadInt64(header, 8); at = 16; }
                        int captured = Marshal.ReadInt32(header, at), wire = Marshal.ReadInt32(header, at + 4);
                        if (captured <= 0 || captured > MaxFrame) continue;
                        var bytes = new byte[captured];
                        Marshal.Copy(data, bytes, 0, captured);
                        Deliver(new CapturedFrame(Stamp(seconds, micros), Math.Max(wire, captured), bytes, _link));
                    }
                    else if (rc != 0)
                    {
                        // -1: an error (the adapter went away); -2: the end of a file, which a live capture has none of
                        if (rc == -1 && PcapNative.pcap_geterr(_handle) is var text && text != IntPtr.Zero)
                            error = Marshal.PtrToStringUTF8(text);
                        error ??= "the capture ended";
                        break;
                    }
                    // the engine's own drop count, now and then (a full buffer during a burst)
                    if (++polls % 64 == 0 && PcapNative.pcap_stats(_handle, out var stats) == 0)
                        Interlocked.Exchange(ref _dropped, stats.Dropped + (long)stats.InterfaceDropped);
                }
            }
            catch (Exception ex) { error = ex.Message; }
            finally
            {
                try { PcapNative.pcap_close(_handle); } catch (Exception) { }
                End(error);
            }
        }

        private static DateTime Stamp(long seconds, long micros)
        {
            long ticks = DateTime.UnixEpoch.Ticks + seconds * TimeSpan.TicksPerSecond + micros * 10;
            return ticks > 0 && ticks <= DateTime.MaxValue.Ticks ? new DateTime(ticks, DateTimeKind.Utc) : DateTime.UtcNow;
        }

        private static string CString(byte[] buffer)
        {
            int end = Array.IndexOf(buffer, (byte)0);
            return Encoding.UTF8.GetString(buffer, 0, end < 0 ? buffer.Length : end).Trim();
        }
    }

    // ================================================================== Windows without Npcap: a raw socket

    /// <summary>SIO_RCVALL on a raw IPv4 socket bound to the interface's address: every IPv4 packet this computer
    /// sends or receives there, from the IP header on. Administrators only (Windows' rule for raw sockets).</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private sealed class RawSocketEngine : PacketCapture
    {
        private readonly Socket _socket;
        private readonly CancellationTokenSource _cts = new();

        public override string Engine => "a raw socket (IPv4 packets only)";

        public RawSocketEngine(NetIface iface, bool promiscuous, Action<CapturedFrame> onFrame, Action<string?> onEnd) : base(onFrame, onEnd)
        {
            if (iface.V4 is not { } address)
                throw new CaptureException($"{iface.Name} has no IPv4 address, and without Npcap only IPv4 can be captured.");
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            try
            {
                _socket.ReceiveBufferSize = 4 * 1024 * 1024;
                _socket.Bind(new IPEndPoint(address, 0));
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                // RCVALL_ON (1): the card in promiscuous mode; RCVALL_IPLEVEL (3): this computer's own packets only
                _socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(promiscuous ? 1 : 3), new byte[4]);
            }
            catch (SocketException ex)
            {
                _socket.Dispose();
                throw new CaptureException(ex.SocketErrorCode == SocketError.AccessDenied
                    ? "Windows allows raw sockets to administrators only: start Echoes as administrator, or install Npcap."
                    : $"Couldn't capture on {iface.Name}: {ex.Message}");
            }
            _ = Task.Run(RunAsync);
        }

        public override void Stop()
        {
            base.Stop();
            try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        }

        private async Task RunAsync()
        {
            string? error = null;
            var buffer = new byte[65536];
            try
            {
                while (!Stopping)
                {
                    int n = await _socket.ReceiveAsync(buffer, SocketFlags.None, _cts.Token).ConfigureAwait(false);
                    if (n < 20) continue;
                    Deliver(new CapturedFrame(DateTime.UtcNow, n, buffer.AsSpan(0, n).ToArray(), LinkKind.RawIp));
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { error = ex.Message; }
            finally
            {
                _socket.Dispose();
                _cts.Dispose();
                End(error);
            }
        }
    }

    // ================================================================== Linux: a packet socket

    /// <summary>AF_PACKET / SOCK_RAW bound to the interface: every frame, as libpcap itself reads them. A device with
    /// no link-layer header (a tunnel) hands over packets from the IP header on.</summary>
    private sealed class LinuxEngine : PacketCapture
    {
        private const int AF_PACKET = 17, SOCK_RAW = 3, SOL_PACKET = 263, PACKET_ADD_MEMBERSHIP = 1, PACKET_MR_PROMISC = 1;
        private const int SOL_SOCKET = 1, SO_RCVBUF = 8, MSG_TRUNC = 0x20;
        private const ushort ETH_P_ALL_BE = 0x0300;   // htons(ETH_P_ALL)
        private const short POLLIN = 1;
        private const int EPERM = 1, EACCES = 13, EINTR = 4, ENETDOWN = 100;
        private const ushort ARPHRD_ETHER = 1, ARPHRD_LOOPBACK = 772;
        private const byte PACKET_OUTGOING = 4;

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct SockAddrLl
        {
            public ushort Family, Protocol;
            public int IfIndex;
            public ushort HaType;
            public byte PktType, HaLen;
            public ulong Addr;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct PacketMreq
        {
            public int IfIndex;
            public ushort Type, ALen;
            public ulong Address;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PollFd
        {
            public int Fd;
            public short Events, Revents;
        }

        [DllImport("libc", EntryPoint = "socket", SetLastError = true)]
        private static extern int OpenSocket(int domain, int type, int protocol);

        [DllImport("libc", EntryPoint = "bind", SetLastError = true)]
        private static extern int Bind(int fd, ref SockAddrLl address, int length);

        [DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)]
        private static extern int SetOption(int fd, int level, int name, ref PacketMreq value, int length);

        [DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)]
        private static extern int SetOption(int fd, int level, int name, ref int value, int length);

        [DllImport("libc", EntryPoint = "poll", SetLastError = true)]
        private static extern int Poll(ref PollFd fds, nuint count, int timeoutMs);

        [DllImport("libc", EntryPoint = "recvfrom", SetLastError = true)]
        private static extern nint ReceiveFrom(int fd, byte[] buffer, nuint length, int flags, ref SockAddrLl from, ref int fromLength);

        [DllImport("libc", EntryPoint = "close")]
        private static extern int Close(int fd);

        private readonly int _fd;
        private readonly string _name;

        public override string Engine => "a packet socket";

        public LinuxEngine(NetIface iface, bool promiscuous, Action<CapturedFrame> onFrame, Action<string?> onEnd) : base(onFrame, onEnd)
        {
            _name = iface.Name;
            int index = iface.Index > 0 ? iface.Index : (int)NetIface.IndexOf(iface.Name);
            if (index <= 0) throw new CaptureException($"{iface.Name} isn't there any more.");

            _fd = OpenSocket(AF_PACKET, SOCK_RAW, ETH_P_ALL_BE);
            if (_fd < 0)
            {
                int errno = Marshal.GetLastPInvokeError();
                throw new CaptureException(errno is EPERM or EACCES
                    ? "Capturing needs root or the CAP_NET_RAW capability: start Echoes with sudo, or give it the capability once: "
                      + $"sudo setcap cap_net_raw+ep \"{Environment.ProcessPath ?? "Echoes"}\""
                    : $"Couldn't open a packet socket (error {errno}).");
            }
            var address = new SockAddrLl { Family = AF_PACKET, Protocol = ETH_P_ALL_BE, IfIndex = index };
            if (Bind(_fd, ref address, 20) != 0)
            {
                int errno = Marshal.GetLastPInvokeError();
                Close(_fd);
                throw new CaptureException($"Couldn't capture on {iface.Name} (error {errno}).");
            }
            int buffer = 8 * 1024 * 1024;   // the kernel caps it at net.core.rmem_max
            SetOption(_fd, SOL_SOCKET, SO_RCVBUF, ref buffer, 4);
            if (promiscuous)
            {
                var membership = new PacketMreq { IfIndex = index, Type = PACKET_MR_PROMISC };
                SetOption(_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, ref membership, 16);   // dropped again when the socket closes
            }
            new Thread(Run) { IsBackground = true, Name = "Echoes capture" }.Start();
        }

        private void Run()
        {
            string? error = null;
            var buffer = new byte[MaxFrame];
            var poll = new PollFd { Fd = _fd, Events = POLLIN };
            try
            {
                while (!Stopping)
                {
                    poll.Revents = 0;
                    int ready = Poll(ref poll, 1, 200);
                    if (ready == 0) continue;
                    if (ready < 0)
                    {
                        if (Marshal.GetLastPInvokeError() == EINTR) continue;
                        error = $"the capture failed (error {Marshal.GetLastPInvokeError()})";
                        break;
                    }
                    var from = default(SockAddrLl);
                    int fromLength = 20;
                    // MSG_TRUNC: the frame's real length even when it is longer than the buffer
                    nint n = ReceiveFrom(_fd, buffer, (nuint)buffer.Length, MSG_TRUNC, ref from, ref fromLength);
                    if (n < 0)
                    {
                        int errno = Marshal.GetLastPInvokeError();
                        if (errno == EINTR) continue;
                        error = errno == ENETDOWN ? $"{_name} went down" : $"the capture failed (error {errno})";
                        break;
                    }
                    if (n == 0) continue;
                    // the loopback device shows every packet twice, once going out and once coming in: one is enough
                    if (from.HaType == ARPHRD_LOOPBACK && from.PktType == PACKET_OUTGOING) continue;
                    int captured = (int)Math.Min(n, buffer.Length);
                    var link = from.HaType is ARPHRD_ETHER or ARPHRD_LOOPBACK ? LinkKind.Ethernet : LinkKind.RawIp;
                    Deliver(new CapturedFrame(DateTime.UtcNow, (int)Math.Min(n, int.MaxValue), buffer.AsSpan(0, captured).ToArray(), link));
                }
            }
            catch (Exception ex) { error = ex.Message; }
            finally
            {
                Close(_fd);
                End(error);
            }
        }
    }
}
