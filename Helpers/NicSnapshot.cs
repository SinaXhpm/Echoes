using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Echoes.Helpers;

/// <summary>
/// The IPv4 addresses of the network adapters that are up (loopback left out), read once and shared for a second.
/// Enumerating adapters costs ~20 ms on a machine with many virtual / VPN adapters, and a tab switch to Web Server or
/// Proxy used to do it two or three times on the UI thread (bind list, share URLs, catcher URLs).
/// </summary>
public static class NicSnapshot
{
    private static (long At, (string Name, IPAddress Address)[] V4)? s_last;
    private static readonly object s_gate = new();

    public static (string Name, IPAddress Address)[] UpIPv4()
    {
        lock (s_gate)
        {
            if (s_last is { } last && Environment.TickCount64 - last.At < 1000) return last.V4;
        }
        var list = new List<(string, IPAddress)>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork) list.Add((ni.Name, ua.Address));
            }
        }
        catch { /* GetIPProperties can throw on restricted platforms: callers keep loopback / "all" */ }
        var v4 = list.ToArray();
        lock (s_gate) s_last = (Environment.TickCount64, v4);
        return v4;
    }
}
