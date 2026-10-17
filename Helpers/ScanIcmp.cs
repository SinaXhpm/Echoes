using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Echoes.Helpers;

/// <summary>
/// Linux / Android: which ICMP error ended a probe, and who sent it. With IP_RECVERR set, the kernel queues every
/// ICMP error for the socket (type, code, sender), which a plain errno can't tell apart:
/// <list type="bullet">
/// <item>TCP: ECONNREFUSED is either the host's RST (closed) or a firewall's "port unreachable" (iptables' default
/// REJECT — filtered, as nmap's SYN scan reports it); with the queue empty it was the RST.</item>
/// <item>UDP: without IP_RECVERR a connected socket hears only "hard" errors, so a firewall's "host unreachable"
/// looked like silence (open|filtered instead of filtered).</item>
/// </list>
/// Other platforms report what the OS reports (Windows hands a UDP socket only "port unreachable").
/// Blittable structs + DllImport only (trim/AOT-safe); nint/nuint keep the layout right on 64- and 32-bit ABIs.
/// </summary>
internal static class ScanIcmp
{
    public static bool Supported => OperatingSystem.IsLinux() || OperatingSystem.IsAndroid();

    /// <summary>An ICMP error in ICMPv4 numbering (ICMPv6 is mapped) and the address that sent it.</summary>
    public readonly record struct Error(int Type, int Code, IPAddress? From)
    {
        public bool PortUnreachable => Type == 3 && Code == 3;

        /// <summary>nmap's reason name for this error.</summary>
        public string Reason => Type switch
        {
            3 => Code switch
            {
                0 or 6 => "net-unreach",
                1 or 7 => "host-unreach",
                2 => "proto-unreach",
                3 => "port-unreach",
                9 => "net-prohibited",
                10 => "host-prohibited",
                13 => "admin-prohibited",
                _ => "unreach",
            },
            11 => "time-exceeded",
            _ => "icmp-error",
        };
    }

    private const int SOL_IP = 0, IP_RECVERR = 11, SOL_IPV6 = 41, IPV6_RECVERR = 25, MSG_DONTWAIT = 0x40, MSG_ERRQUEUE = 0x2000;
    private const byte SO_EE_ORIGIN_ICMP = 2, SO_EE_ORIGIN_ICMP6 = 3;
    private const ushort AF_INET = 2, AF_INET6 = 10;   // Linux values

    /// <summary>Ask the kernel to queue ICMP errors for this socket. No-op off Linux/Android; never throws.</summary>
    public static void Enable(Socket socket)
    {
        if (!Supported) return;
        try
        {
            bool v6 = socket.AddressFamily == AddressFamily.InterNetworkV6;
            socket.SetRawSocketOption(v6 ? SOL_IPV6 : SOL_IP, v6 ? IPV6_RECVERR : IP_RECVERR, BitConverter.GetBytes(1));
        }
        catch { }
    }

    /// <summary>The ICMP error queued for this socket, if any (consumes it). Never throws.</summary>
    public static Error? Read(Socket socket)
    {
        if (!Supported) return null;
        var data = new byte[128];      // the offending packet's head — unused, but recvmsg needs room for it
        var control = new byte[256];   // cmsg: sock_extended_err + SO_EE_OFFENDER sockaddr
        var iov = new IoVec[1];
        var hData = GCHandle.Alloc(data, GCHandleType.Pinned);
        var hCtl = GCHandle.Alloc(control, GCHandleType.Pinned);
        var hIov = GCHandle.Alloc(iov, GCHandleType.Pinned);
        try
        {
            iov[0] = new IoVec { Base = hData.AddrOfPinnedObject(), Len = (nuint)data.Length };
            var msg = new MsgHdr
            {
                Iov = hIov.AddrOfPinnedObject(), IovLen = 1,
                Control = hCtl.AddrOfPinnedObject(), ControlLen = (nuint)control.Length,
            };
            if (RecvMsg((int)socket.Handle, ref msg, MSG_ERRQUEUE | MSG_DONTWAIT) < 0) return null;
            return Parse(control, (int)Math.Min((ulong)msg.ControlLen, (ulong)control.Length));
        }
        catch { return null; }   // DllNotFound / EntryPointNotFound / a disposed socket
        finally
        {
            hData.Free(); hCtl.Free(); hIov.Free();
        }
    }

    private static Error? Parse(byte[] c, int len)
    {
        int word = IntPtr.Size;   // cmsg_len is a size_t and cmsg data is size_t-aligned
        int hdr = word + 8;       // sizeof(struct cmsghdr)
        for (int off = 0; off + hdr <= len;)
        {
            long cmsgLen = word == 8 ? BitConverter.ToInt64(c, off) : BitConverter.ToInt32(c, off);
            // (len - off, not off + cmsgLen: a length near long.MaxValue wrapped that sum negative and passed)
            if (cmsgLen < hdr || cmsgLen > len - off) break;
            int level = BitConverter.ToInt32(c, off + word);
            int type = BitConverter.ToInt32(c, off + word + 4);
            // struct sock_extended_err { u32 errno; u8 origin, type, code, pad; u32 info, data; } followed by
            // SO_EE_OFFENDER: the sockaddr of whoever sent the ICMP error.
            int d = off + hdr;
            if (level == SOL_IP && type == IP_RECVERR && cmsgLen >= hdr + 16 + 8 && c[d + 4] == SO_EE_ORIGIN_ICMP)
            {
                IPAddress? from = BitConverter.ToUInt16(c, d + 16) == AF_INET ? new IPAddress(c.AsSpan(d + 20, 4)) : null;
                return new Error(c[d + 5], c[d + 6], from);
            }
            if (level == SOL_IPV6 && type == IPV6_RECVERR && cmsgLen >= hdr + 16 + 8 && c[d + 4] == SO_EE_ORIGIN_ICMP6)
            {
                IPAddress? from = cmsgLen >= hdr + 16 + 24 && BitConverter.ToUInt16(c, d + 16) == AF_INET6
                    ? new IPAddress(c.AsSpan(d + 24, 16)) : null;
                byte t6 = c[d + 5], code6 = c[d + 6];
                // ICMPv6 → ICMPv4 numbers: destination unreachable (1): 0 no route, 1 admin prohibited, 3 address
                // unreachable, 4 port unreachable, 5/6 policy / reject route; time exceeded (3).
                return t6 switch
                {
                    1 => new Error(3, code6 switch { 0 => 0, 3 => 1, 4 => 3, _ => 13 }, from),
                    3 => new Error(11, code6, from),
                    _ => new Error(256 + t6, code6, from),
                };
            }
            off += (int)((cmsgLen + word - 1) & ~(long)(word - 1));   // CMSG_NXTHDR alignment
        }
        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoVec { public nint Base; public nuint Len; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MsgHdr
    {
        public nint Name; public uint NameLen;
        public nint Iov; public nuint IovLen;
        public nint Control; public nuint ControlLen;
        public int Flags;
    }

    [DllImport("libc", EntryPoint = "recvmsg")]
    private static extern nint RecvMsg(int sockfd, ref MsgHdr msg, int flags);
}
