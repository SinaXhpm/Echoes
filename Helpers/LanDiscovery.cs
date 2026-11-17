using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;

namespace Echoes.Helpers;

/// <summary>A device found on an interface's network, as it stands at one moment of a search.</summary>
/// <param name="Name">The best name known for it, or empty.</param>
/// <param name="NameSource">Where <paramref name="Name"/> came from ("DNS", "mDNS", "NetBIOS", "LLMNR", "UPnP").</param>
/// <param name="Details">What else it said about itself: a UPnP model, the services it announces, its workgroup.</param>
/// <param name="FoundBy">How it was found, in the order it happened ("ARP · mDNS · SSDP").</param>
public sealed record LanDevice(string Ip, string Mac, string Vendor, string Name, string NameSource, string Details,
                               string FoundBy, bool IsThisDevice, bool IsGateway, bool Answered)
{
    /// <summary>This address was reported as a device and turned out not to be one (a router answered for it, see
    /// <see cref="ProxyArpFilter"/>): it is to be taken out of the list again.</summary>
    public bool Withdrawn { get; init; }
}

/// <summary>How a search ended.</summary>
/// <param name="ProxyAnswers">ARP answers left out because a router gave them for addresses that aren't its own
/// (<see cref="ProxyArpFilter"/>); 0 on an ordinary network.</param>
public sealed record LanDiscoveryResult(int Devices, int Addresses, string Network, bool WholeSubnet, TimeSpan Elapsed, int ProxyAnswers = 0);

/// <summary>
/// Tells a router that answers ARP for every address from real devices. Cloud networks (Azure's) and hotspots that
/// keep their clients apart do that (proxy ARP): every address of the subnet "is at" the router's own MAC, and a sweep
/// would list a device for each. One MAC that answers for more than <see cref="Limit"/> addresses isn't that many
/// devices: from then on its answers are left out, and the ones already reported are withdrawn. (A computer with a
/// few addresses on one adapter stays under the limit; the gateway's own address is never asked about here.)
/// Not thread-safe: the caller locks.
/// </summary>
internal sealed class ProxyArpFilter
{
    /// <summary>The most addresses one MAC may answer for and still be taken for a device with several addresses.</summary>
    public const int Limit = 12;

    private readonly Dictionary<string, List<string>> _byMac = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _proxies = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The answers that were left out or withdrawn.</summary>
    public int Dropped { get; private set; }

    /// <summary>
    /// An ARP answer: <paramref name="ip"/> is at <paramref name="mac"/>. True: it is a device as far as this can
    /// tell. False: the MAC is a router's that answers for everybody; <paramref name="withdraw"/> then holds the
    /// addresses accepted for it before (once, at the moment the limit is passed).
    /// </summary>
    public bool Accept(string ip, string mac, out IReadOnlyList<string> withdraw)
    {
        withdraw = Array.Empty<string>();
        if (_proxies.Contains(mac))
        {
            Dropped++;
            return false;
        }
        if (!_byMac.TryGetValue(mac, out var addresses)) _byMac[mac] = addresses = new List<string>(4);
        if (addresses.Contains(ip)) return true;   // the same answer again (a second read of the table)
        if (addresses.Count < Limit)
        {
            addresses.Add(ip);
            return true;
        }
        _proxies.Add(mac);
        _byMac.Remove(mac);
        withdraw = addresses;
        Dropped += addresses.Count + 1;
        return false;
    }
}

/// <summary>
/// Finds the devices on the network of one interface, the way the usual LAN tools do together, with no privileges:
/// <list type="bullet">
/// <item><b>ARP.</b> A datagram goes to every address of the interface's IPv4 subnet (at most 1,022 of them). Nothing
/// has to answer it: to send it, the system itself asks "who has this address?" on the wire, and every device that is
/// there answers that, firewall or not. The answers are read back from the system's neighbor table
/// (<see cref="ScanNeighbors"/>, this interface's entries only).</item>
/// <item><b>mDNS / DNS-SD</b> (Bonjour): one multicast question for the services on the link; what answers names itself
/// and what it offers (AirPlay, printers, Chromecast, file sharing …).</item>
/// <item><b>SSDP / UPnP:</b> one multicast search; routers, TVs, consoles and NAS boxes answer, and their own
/// description (asked only from the device that answered, over the same interface) gives a friendly name and model.</item>
/// <item><b>Names</b> for every address found: a reverse lookup at the interface's own DNS server when that is on the
/// link (a home router knows its DHCP clients), reverse mDNS and LLMNR, and a NetBIOS node status.</item>
/// </list>
/// Everything is sent from the chosen interface (<see cref="NetIface.TryBind"/> / <see cref="NetIface.TryBindMulticast"/>),
/// and only to that interface's own subnet and the link-local multicast groups. IPv4 only. Every name and string a
/// device sends is remote text: cleaned and capped before it is kept.
/// </summary>
public static class LanDiscovery
{
    /// <summary>The most addresses swept (a /22): a bigger subnet gets the block of that size around this device.</summary>
    public const int MaxAddresses = 1022;

    private const int SweepMs = 3200;      // the ARP rounds and the multicast listening
    private const int NameMs = 1600;       // each name lookup
    private const int ConfirmsAtOnce = 16; // cache entries checked at once (Run.ConfirmAsync)
    private static readonly IPEndPoint MdnsGroup = new(IPAddress.Parse("224.0.0.251"), 5353);
    private static readonly IPEndPoint SsdpGroup = new(IPAddress.Parse("239.255.255.250"), 1900);

    /// <summary>Whether a search can work here: it needs the system's neighbor table (Windows, desktop Linux).</summary>
    public static bool IsAvailable => NetTables.CanReadNeighbors;

    /// <summary>
    /// Searches <paramref name="iface"/>'s network. <paramref name="onDevice"/> is called (from pool threads) each time
    /// a device is found or learns something new, with its current state. Returns when the search is over or
    /// <paramref name="ct"/> is cancelled (what was found stands). Throws <see cref="NetIfaceException"/> when the
    /// interface can't be searched (no IPv4 network, or it can't be sent from).
    /// </summary>
    public static async Task<LanDiscoveryResult> RunAsync(NetIface iface, Action<LanDevice> onDevice, CancellationToken ct)
    {
        if (iface.V4 is not { } own)
            throw new NetIfaceException($"{iface.Name} has no IPv4 address: devices are searched on an IPv4 network.");
        if (iface.Subnet4(MaxAddresses, out bool whole) is not { } subnet)
            throw new NetIfaceException($"{iface.Name}'s network ({own}/{iface.Prefix4}) has no other addresses to search.");

        var run = new Run(iface, onDevice);
        var clock = Stopwatch.StartNew();
        run.Found(own, iface.Mac, "this device", answered: true);

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = stop.Token;
        var tasks = new List<Task>
        {
            Guard(run.ArpSweepAsync(subnet.Hosts, token)),
            Guard(run.MdnsAsync(token)),
            Guard(run.SsdpAsync(token)),
        };
        try { await Task.WhenAll(tasks).ConfigureAwait(false); }
        finally
        {
            // the name lookups started for the last devices found get their time, then everything ends
            try { await run.NamesDoneAsync(ct).ConfigureAwait(false); }
            catch (Exception e) when (e is OperationCanceledException or TimeoutException) { }
            stop.Cancel();
        }
        return new LanDiscoveryResult(run.Count, subnet.Hosts.Count, $"{subnet.Network}/{subnet.Prefix}", whole, clock.Elapsed, run.ProxyAnswers);

        // one method failing (a socket the system refuses) must not end the others
        static async Task Guard(Task t)
        {
            try { await t.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch (NetIfaceException) { throw; }
            catch (Exception) { }
        }
    }

    // ------------------------------------------------------------------ one search

    private sealed class Run(NetIface iface, Action<LanDevice> onDevice)
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, Dev> _devices = new(StringComparer.Ordinal);
        private readonly List<Task> _nameTasks = new();
        private readonly SemaphoreSlim _nameSlots = new(24, 24);
        private readonly SemaphoreSlim _confirmSlots = new(ConfirmsAtOnce, ConfirmsAtOnce);
        private readonly ConcurrentQueue<IPAddress> _mdnsReverse = new();   // addresses the mDNS socket should ask the name of
        private HttpClient? _http;
        private int _descriptions;

        private readonly ProxyArpFilter _proxyArp = new();

        public int Count { get { lock (_gate) return _devices.Count; } }
        public int ProxyAnswers { get { lock (_gate) return _proxyArp.Dropped; } }

        private sealed class Dev(IPAddress address)
        {
            public readonly IPAddress Address = address;
            public string Mac = string.Empty;
            public bool Answered;
            public readonly List<string> FoundBy = new(4);
            public readonly SortedDictionary<int, (string Source, string Name)> Names = new();   // by preference
            public readonly List<string> Details = new(3);
        }

        // ---- the table of what was found ----

        /// <summary>A device at <paramref name="address"/> (on this interface's subnet only) was seen by
        /// <paramref name="how"/>; its name lookups start the first time.</summary>
        public void Found(IPAddress address, string? mac, string how, bool answered, CancellationToken names = default)
        {
            if (!iface.OnLink4(address)) return;
            bool isNew, changed = false;
            Dev dev;
            lock (_gate)
            {
                string key = address.ToString();
                isNew = !_devices.TryGetValue(key, out dev!);
                if (isNew) _devices[key] = dev = new Dev(address);
                if (!dev.FoundBy.Contains(how)) { dev.FoundBy.Add(how); changed = true; }
                if (!string.IsNullOrEmpty(mac) && dev.Mac.Length == 0) { dev.Mac = mac; changed = true; }
                if (answered && !dev.Answered) { dev.Answered = true; changed = true; }
            }
            if (isNew || changed) Report(dev);
            if (isNew && how != "this device") StartNames(address, names);
        }

        /// <summary>An ARP answer or cache entry for <paramref name="address"/>: a device, unless its MAC answers for
        /// so many addresses that it is a router answering for everybody (<see cref="ProxyArpFilter"/>). This device's
        /// own address and the gateway's always count.</summary>
        private void FoundByArp(IPAddress address, string mac, string how, bool answered, CancellationToken names)
        {
            if (mac.Length > 0 && !address.Equals(iface.V4) && !address.Equals(iface.Gateway4))
            {
                bool accepted;
                IReadOnlyList<string> withdraw;
                lock (_gate) accepted = _proxyArp.Accept(address.ToString(), mac, out withdraw);
                foreach (string ip in withdraw) Withdraw(ip);
                if (!accepted) return;
            }
            Found(address, mac, how, answered, names);
        }

        // Takes back an address that only ARP reported (one that also announced itself by mDNS or SSDP is a device).
        private void Withdraw(string ip)
        {
            Dev? dev;
            lock (_gate)
            {
                if (!_devices.TryGetValue(ip, out dev) || dev.FoundBy.Exists(how => how is not ("ARP" or "ARP cache"))) return;
                _devices.Remove(ip);
            }
            try
            {
                onDevice(new LanDevice(ip, dev.Mac, string.Empty, string.Empty, string.Empty, string.Empty, string.Join(" · ", dev.FoundBy),
                                       false, false, false) { Withdrawn = true });
            }
            catch (Exception) { }
        }

        private void Named(IPAddress address, int preference, string source, string? name)
        {
            name = RemoteText.Clean(name?.Trim().TrimEnd('.'), 80);
            if (name.Length == 0) return;
            Dev? dev;
            lock (_gate)
            {
                if (!_devices.TryGetValue(address.ToString(), out dev) || dev.Names.ContainsKey(preference)) return;
                dev.Names[preference] = (source, name);
            }
            Report(dev);
        }

        private void Detail(IPAddress address, string? text)
        {
            text = RemoteText.Clean(text?.Trim(), 120);
            if (text.Length == 0) return;
            Dev? dev;
            lock (_gate)
            {
                if (!_devices.TryGetValue(address.ToString(), out dev) || dev.Details.Count >= 6 || dev.Details.Contains(text)) return;
                dev.Details.Add(text);
            }
            Report(dev);
        }

        private void Report(Dev dev)
        {
            LanDevice snapshot;
            lock (_gate)
            {
                var best = dev.Names.Count > 0 ? dev.Names.First().Value : (Source: string.Empty, Name: string.Empty);
                // the names it has by other ways (a PC is "fake-tv.local" to mDNS and "FAKEPC" to NetBIOS), then what it said
                var more = dev.Names.Values.Skip(1).Where(n => !n.Name.Equals(best.Name, StringComparison.OrdinalIgnoreCase))
                                           .Select(n => $"{n.Source}: {n.Name}").Concat(dev.Details);
                snapshot = new LanDevice(dev.Address.ToString(), dev.Mac, ScanOui.Vendor(dev.Mac), best.Name, best.Source,
                                         string.Join(" · ", more), string.Join(" · ", dev.FoundBy),
                                         dev.Address.Equals(iface.V4), dev.Address.Equals(iface.Gateway4), dev.Answered);
            }
            try { onDevice(snapshot); } catch (Exception) { }
        }

        // ---- ARP: make the system ask, read what answered ----

        public async Task ArpSweepAsync(List<IPAddress> hosts, CancellationToken ct)
        {
            var before = ScanNeighbors.Snapshot(iface);
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (!iface.TryBind(socket, out string? why))
                throw NetIfaceException.From(iface, why ?? $"can't send through {iface.Name}");
            byte[] nudge = { 0 };
            var seen = new HashSet<string>(StringComparer.Ordinal);   // addresses reported as answering (under its own lock)
            long start = Stopwatch.GetTimestamp();
            double Elapsed() => Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            // What the cache held before: the system keeps using such an entry without asking again for a while, so
            // the sweep alone can't tell a device that is there from one that left an hour ago. Each is asked directly.
            var checks = new List<Task>();
            foreach (var (ip, entry) in before)
                if (IPAddress.TryParse(ip, out var known) && iface.OnLink4(known) && !known.Equals(iface.V4))
                    checks.Add(Task.Run(() => ConfirmAsync(known, entry.Mac, seen, ct), CancellationToken.None));

            // Two rounds: a phone or an IoT device in power save often misses the first question. The sending runs
            // beside the reading, so a system that is slow to queue a thousand datagrams doesn't hold the answers back.
            var sending = Task.Run(async () =>
            {
                for (int round = 0; round < 2 && !ct.IsCancellationRequested; round++)
                {
                    if (round == 1)
                    {
                        double wait = SweepMs * 2 / 5 - Elapsed();
                        if (wait > 0) await Task.Delay((int)wait, ct).ConfigureAwait(false);
                    }
                    int sent = 0;
                    foreach (var host in hosts)
                    {
                        if (ct.IsCancellationRequested) return;
                        if (host.Equals(iface.V4)) continue;
                        lock (seen) if (seen.Contains(host.ToString())) continue;
                        // (the discard port: the datagram itself is of no interest, the ARP request before it is)
                        try { socket.SendTo(nudge, new IPEndPoint(host, 9)); }
                        catch (Exception e) when (e is SocketException or ObjectDisposedException) { }
                        // paced: a burst of a thousand unresolved addresses overflows the system's neighbor queue
                        if (++sent % 48 == 0) await Task.Delay(20, ct).ConfigureAwait(false);
                    }
                }
            }, CancellationToken.None);

            // Read the table as the answers come in: for the planned time, and (a slow sender) until a second after
            // the last question went out, within three times the plan.
            double end = SweepMs;
            while (Elapsed() < end)
            {
                await Task.Delay(300, ct).ConfigureAwait(false);
                Read(final: false);
                if (!sending.IsCompleted) end = Math.Min(Math.Max(end, Elapsed() + 1200), SweepMs * 3);
            }
            try { await Task.WhenAll(checks).WaitAsync(TimeSpan.FromMilliseconds(600), ct).ConfigureAwait(false); }
            catch (Exception e) when (e is TimeoutException or OperationCanceledException) { }
            Read(final: true);
            try { await sending.WaitAsync(TimeSpan.FromMilliseconds(200), CancellationToken.None).ConfigureAwait(false); }
            catch (Exception) { }

            void Read(bool final)
            {
                foreach (var (ip, entry) in ScanNeighbors.Snapshot(iface))
                {
                    if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork) continue;
                    // Proof that it answered now: an entry that wasn't there before the sweep, or one the system has
                    // just confirmed (Windows says so). An older entry waits for its own check (ConfirmAsync).
                    bool fresh = !before.ContainsKey(ip) || (entry.Confirmed && !before[ip].Confirmed);
                    if (fresh)
                    {
                        lock (seen) if (!seen.Add(ip)) continue;
                        FoundByArp(address, entry.Mac, "ARP", answered: true, ct);
                    }
                    else if (final)
                    {
                        lock (seen) if (seen.Contains(ip)) continue;
                        FoundByArp(address, entry.Mac, "ARP cache", answered: false, ct);   // was there; not confirmed by this search
                    }
                }
            }
        }

        // Is a device the cache already knew still there? Windows: an ARP request of its own (SendARP resolves the
        // entry again and waits for the answer). Elsewhere, where only root may send ARP: an echo request.
        // A cache can hold hundreds of entries, and SendARP blocks its thread for about three seconds for a device that
        // has gone, with no way to cancel it: a few checks run at once (ConfirmsAtOnce), each SendARP on a thread of its
        // own rather than the pool's, and none starts once the search is over.
        private async Task ConfirmAsync(IPAddress address, string mac, HashSet<string> seen, CancellationToken ct)
        {
            try { await _confirmSlots.WaitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            bool there = false;
            try
            {
                ct.ThrowIfCancellationRequested();
                if (OperatingSystem.IsWindows() && iface.V4 is { } source)
                {
                    uint destination = BitConverter.ToUInt32(address.GetAddressBytes(), 0), from = BitConverter.ToUInt32(source.GetAddressBytes(), 0);
                    var answer = new byte[6];
                    there = await Task.Factory.StartNew(() =>
                    {
                        int length = answer.Length;
                        return SendARP(destination, from, answer, ref length) == 0 && length == 6;
                    }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).ConfigureAwait(false);
                    if (there) mac = string.Join(":", answer.Select(b => b.ToString("X2")));
                }
                else
                {
                    var ping = await IcmpPinger.SendAsync(address, 1200, ct, via: iface).ConfigureAwait(false);
                    there = ping.Success;
                }
            }
            catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or OperationCanceledException) { }
            finally { _confirmSlots.Release(); }
            if (!there || ct.IsCancellationRequested) return;
            lock (seen) if (!seen.Add(address.ToString())) return;
            FoundByArp(address, mac, "ARP", answered: true, ct);
        }

        // DWORD SendARP(IPAddr DestIP, IPAddr SrcIP, PVOID pMacAddr, PULONG PhyAddrLen): the addresses as they are on
        // the wire; the source address chooses the interface. Blocks until the answer or about three seconds.
        [System.Runtime.InteropServices.DllImport("iphlpapi.dll")]
        private static extern int SendARP(uint destination, uint source, byte[] mac, ref int macLength);

        // ---- names, for every address found ----

        private void StartNames(IPAddress address, CancellationToken ct)
        {
            _mdnsReverse.Enqueue(address);
            var task = Task.Run(async () =>
            {
                try { await _nameSlots.WaitAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                try
                {
                    await Task.WhenAll(Quiet(ReverseDnsAsync(address, ct)), Quiet(NetbiosAsync(address, ct)), Quiet(LlmnrAsync(address, ct)))
                              .ConfigureAwait(false);
                }
                finally { _nameSlots.Release(); }
            }, CancellationToken.None);
            lock (_nameTasks) _nameTasks.Add(task);

            static async Task Quiet(Task t)
            {
                try { await t.ConfigureAwait(false); }
                catch (Exception) { }
            }
        }

        public async Task NamesDoneAsync(CancellationToken ct)
        {
            Task[] pending;
            lock (_nameTasks) pending = _nameTasks.ToArray();
            await Task.WhenAll(pending).WaitAsync(TimeSpan.FromMilliseconds(NameMs + 600), ct).ConfigureAwait(false);
        }

        // The interface's own DNS server, when it is on the link: a home router answers for the names its DHCP clients gave.
        private async Task ReverseDnsAsync(IPAddress address, CancellationToken ct)
        {
            var server = iface.DnsServers.FirstOrDefault(iface.OnLink4);
            if (server is null || !ResolverSpec.TryParse(server.ToString(), out var spec, out _)) return;
            var r = await SecureDns.QueryAsync(spec, DnsWire.ArpaName(address), QueryType.PTR, ct, TimeSpan.FromMilliseconds(NameMs), iface)
                                   .ConfigureAwait(false);
            if (r.Ok && r.OfType("PTR").FirstOrDefault() is { } ptr) Named(address, 0, "DNS", ptr.Value);
        }

        // NBSTAT: the machine's own NetBIOS name table (Windows PCs, Samba, many printers and NAS boxes).
        private async Task NetbiosAsync(IPAddress address, CancellationToken ct)
        {
            byte[]? reply = await AskAsync(new IPEndPoint(address, 137), ScanPayloads.Udp(137), ct).ConfigureAwait(false);
            if (reply is null) return;
            var (host, group) = Nbstat(reply);
            Named(address, 2, "NetBIOS", host);
            if (group.Length > 0) Detail(address, "workgroup " + group);
        }

        // LLMNR, asked straight at the device: Windows answers a reverse question with its computer name.
        private async Task LlmnrAsync(IPAddress address, CancellationToken ct)
        {
            ushort id = (ushort)RandomNumberGenerator.GetInt32(1, 65536);
            byte[]? reply = await AskAsync(new IPEndPoint(address, 5355), Question(DnsWire.ArpaName(address), 12, id, unicastReply: false), ct)
                .ConfigureAwait(false);
            if (reply is null || reply.Length < 12 || reply[0] != (byte)(id >> 8) || reply[1] != (byte)id) return;
            foreach (var rr in Records(reply))
                if (rr.Type == 12 && rr.Target is { Length: > 0 } name) { Named(address, 3, "LLMNR", name); break; }
        }

        // One datagram to one device from this interface, and its answer (null: none in time).
        private async Task<byte[]?> AskAsync(IPEndPoint to, byte[] question, CancellationToken ct)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (!iface.TryBind(socket, out _)) return null;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(NameMs);
            try
            {
                await socket.ConnectAsync(to, deadline.Token).ConfigureAwait(false);
                await socket.SendAsync(question, SocketFlags.None, deadline.Token).ConfigureAwait(false);
                byte[] buffer = new byte[1500];
                int n = await socket.ReceiveAsync(buffer, SocketFlags.None, deadline.Token).ConfigureAwait(false);
                return buffer.AsSpan(0, n).ToArray();
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException or ObjectDisposedException) { return null; }
        }

        // ---- mDNS / DNS-SD ----

        public async Task MdnsAsync(CancellationToken ct)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (!iface.TryBindMulticast(socket, out _)) return;
            // From a port of our own (not 5353), so every responder answers straight back to this socket.
            Send(socket, Question("_services._dns-sd._udp.local", 12, 0, unicastReply: true), MdnsGroup);

            var asked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            byte[] buffer = new byte[9000];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(SweepMs + 600);
            var pump = Task.Run(async () =>
            {
                // the addresses ARP finds meanwhile: who is that? (answered by Apple devices, Linux, many appliances)
                try
                {
                    while (!deadline.IsCancellationRequested)
                    {
                        while (_mdnsReverse.TryDequeue(out var address))
                            Send(socket, Question(DnsWire.ArpaName(address), 12, 0, unicastReply: true), MdnsGroup);
                        await Task.Delay(120, deadline.Token).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) { }
            }, CancellationToken.None);

            try
            {
                while (true)
                {
                    var r = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, deadline.Token).ConfigureAwait(false);
                    if (r.RemoteEndPoint is not IPEndPoint { Address: var from } || !iface.OnLink4(from) || from.Equals(iface.V4)) continue;
                    var records = Records(buffer.AsSpan(0, r.ReceivedBytes));
                    if (records.Count == 0) continue;
                    Found(from, null, "mDNS", answered: true, ct);

                    foreach (var rr in records)
                    {
                        switch (rr.Type)
                        {
                            // its own name: the owner of an address record, or the target of a service
                            case 1 when rr.Address is { } a && a.Equals(from) && rr.Name.EndsWith(".local", StringComparison.OrdinalIgnoreCase):
                                Named(from, 1, "mDNS", rr.Name);
                                break;
                            case 33 when rr.Target is { } host && host.EndsWith(".local", StringComparison.OrdinalIgnoreCase):
                                Named(from, 1, "mDNS", host);
                                break;
                            // the answer to "who is 192.168.1.20?", from that device itself (one device doesn't get to
                            // name another)
                            case 12 when rr.Name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase) && rr.Target is { } ptrHost:
                                if (ArpaAddress(rr.Name) is { } who && who.Equals(from)) Named(who, 1, "mDNS", ptrHost);
                                break;
                            // a kind of service it offers: ask for its instances once (their names are the friendly ones)
                            case 12 when rr.Name.Equals("_services._dns-sd._udp.local", StringComparison.OrdinalIgnoreCase) && rr.Target is { } type:
                                if (asked.Count < 24 && asked.Add(type)) Send(socket, Question(type, 12, 0, unicastReply: true), MdnsGroup);
                                break;
                            // an instance: "Living Room TV._airplay._tcp.local"
                            case 12 when rr.Target is { } instance && instance.EndsWith("." + rr.Name, StringComparison.OrdinalIgnoreCase):
                                Detail(from, ServiceLabel(rr.Name) + ": " + instance[..^(rr.Name.Length + 1)]);
                                break;
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (SocketException) { }
            finally
            {
                deadline.Cancel();
                try { await pump.ConfigureAwait(false); } catch (Exception) { }
            }
        }

        // ---- SSDP / UPnP ----

        public async Task SsdpAsync(CancellationToken ct)
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            if (!iface.TryBindMulticast(socket, out _)) return;
            byte[] search = ScanPayloads.Udp(1900);
            Send(socket, search, SsdpGroup);

            byte[] buffer = new byte[4096];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(SweepMs);
            var again = Task.Delay(500, deadline.Token).ContinueWith(t => { if (!t.IsCanceled) Send(socket, search, SsdpGroup); },
                                                                     TaskScheduler.Default);   // datagrams get lost: once more
            var described = new HashSet<string>(StringComparer.Ordinal);
            var fetches = new List<Task>();
            try
            {
                while (true)
                {
                    var r = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, deadline.Token).ConfigureAwait(false);
                    if (r.RemoteEndPoint is not IPEndPoint { Address: var from } || !iface.OnLink4(from) || from.Equals(iface.V4)) continue;
                    string text = Encoding.Latin1.GetString(buffer, 0, r.ReceivedBytes);
                    if (!text.StartsWith("HTTP/1.", StringComparison.Ordinal)) continue;
                    Found(from, null, "SSDP", answered: true, ct);
                    if (Header(text, "SERVER") is { Length: > 0 } server) Detail(from, server);
                    // Its description, once per device, and only from the device that answered (never wherever a reply
                    // points: a reply naming another host's URL is passed over, and doesn't use up the device's one fetch).
                    if (Header(text, "LOCATION") is { } location
                        && Uri.TryCreate(location, UriKind.Absolute, out var url) && url.Scheme == Uri.UriSchemeHttp
                        && IPAddress.TryParse(url.Host, out var host) && host.Equals(from)
                        && described.Add(from.ToString()) && Interlocked.Increment(ref _descriptions) <= 24)
                        fetches.Add(DescribeAsync(from, url, ct));
                }
            }
            catch (OperationCanceledException) { }
            catch (SocketException) { }
            try { await again.ConfigureAwait(false); } catch (Exception) { }
            try { await Task.WhenAll(fetches).ConfigureAwait(false); } catch (Exception) { }
            _http?.Dispose();
        }

        // A UPnP device description: its friendly name, maker and model. Read as text, at most 64 KB, no XML parser.
        private async Task DescribeAsync(IPAddress from, Uri url, CancellationToken ct)
        {
            try
            {
                var http = LazyInitializer.EnsureInitialized(ref _http, () => new HttpClient(new SocketsHttpHandler
                {
                    UseProxy = false, AllowAutoRedirect = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.None,
                    ConnectTimeout = TimeSpan.FromSeconds(2),
                    ConnectCallback = ServiceDns.ConnectFrom(iface, serviceDns: false),
                }) { Timeout = Timeout.InfiniteTimeSpan });
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(2500);
                using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) return;
                await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                byte[] buffer = new byte[64 * 1024];
                int got = 0, n;
                while (got < buffer.Length && (n = await stream.ReadAsync(buffer.AsMemory(got), deadline.Token).ConfigureAwait(false)) > 0) got += n;
                string xml = Encoding.UTF8.GetString(buffer, 0, got);
                string friendly = Element(xml, "friendlyName"), maker = Element(xml, "manufacturer"), model = Element(xml, "modelName");
                Named(from, 4, "UPnP", friendly);
                string what = (maker + " " + model).Trim();
                if (what.Length > 0 && !what.Equals(friendly, StringComparison.OrdinalIgnoreCase)) Detail(from, what);
            }
            catch (Exception) { }
        }
    }

    // ------------------------------------------------------------------ wire helpers

    private static void Send(Socket socket, byte[] datagram, IPEndPoint to)
    {
        try { socket.SendTo(datagram, to); }
        catch (Exception e) when (e is SocketException or ObjectDisposedException) { }
    }

    // A one-question DNS message as mDNS and LLMNR take it (no EDNS record, no recursion asked).
    internal static byte[] Question(string name, ushort type, ushort id, bool unicastReply)
    {
        var b = new List<byte>(64) { (byte)(id >> 8), (byte)id, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        try { DnsWire.EncodeName(name, b); }
        catch (DnsWireException) { b.Add(0); }
        b.Add((byte)(type >> 8));
        b.Add((byte)type);
        b.Add((byte)(unicastReply ? 0x80 : 0x00));   // mDNS: the top bit of the class asks for a unicast answer
        b.Add(1);
        return b.ToArray();
    }

    internal readonly record struct Record(string Name, int Type, IPAddress? Address, string? Target);

    // Every record of a DNS message (answers, authorities and additionals alike: mDNS puts the useful ones anywhere).
    // Names are read with the packet decoder's reader, which never leaves the message; anything malformed ends the walk.
    internal static List<Record> Records(ReadOnlySpan<byte> m)
    {
        var list = new List<Record>();
        if (m.Length < 12) return list;
        int questions = (m[4] << 8) | m[5];
        int records = ((m[6] << 8) | m[7]) + ((m[8] << 8) | m[9]) + ((m[10] << 8) | m[11]);
        if (questions > 16 || records > 256) return list;
        int at = 12;
        for (int q = 0; q < questions; q++)
        {
            if (PacketDecoder.DnsName(m, ref at) is null || at + 4 > m.Length) return list;
            at += 4;
        }
        for (int i = 0; i < records; i++)
        {
            string? name = PacketDecoder.DnsName(m, ref at);
            if (name is null || at + 10 > m.Length) break;
            int type = (m[at] << 8) | m[at + 1], length = (m[at + 8] << 8) | m[at + 9];
            at += 10;
            if (at + length > m.Length) break;
            IPAddress? address = null;
            string? target = null;
            int data = at;
            switch (type)
            {
                case 1 when length == 4: address = new IPAddress(m.Slice(at, 4)); break;
                case 12: target = PacketDecoder.DnsName(m, ref data); break;
                case 33 when length > 6: data = at + 6; target = PacketDecoder.DnsName(m, ref data); break;
            }
            list.Add(new Record(name, type, address, target));
            at += length;
        }
        return list;
    }

    // "20.1.168.192.in-addr.arpa" → 192.168.1.20
    internal static IPAddress? ArpaAddress(string name)
    {
        var parts = name.Split('.');
        if (parts.Length < 6) return null;
        var b = new byte[4];
        for (int i = 0; i < 4; i++)
            if (!byte.TryParse(parts[3 - i], out b[i])) return null;
        return new IPAddress(b);
    }

    // "_airplay._tcp.local" → "AirPlay"; an unknown type keeps its own name without the underscores.
    internal static string ServiceLabel(string type)
    {
        string service = type.Split('.')[0].TrimStart('_');
        return service.ToLowerInvariant() switch
        {
            "airplay" or "raop" => "AirPlay",
            "googlecast" => "Chromecast",
            "ipp" or "ipps" or "printer" or "pdl-datastream" => "Printer",
            "scanner" or "uscan" or "uscans" => "Scanner",
            "smb" => "File sharing (SMB)",
            "afpovertcp" => "File sharing (AFP)",
            "ssh" or "sftp-ssh" => "SSH",
            "http" or "https" => "Web",
            "hap" or "homekit" => "HomeKit",
            "spotify-connect" => "Spotify",
            "companion-link" or "apple-mobdev2" => "Apple device",
            "workstation" => "Workstation",
            "rdlink" or "rfb" => "Remote desktop",
            "mqtt" => "MQTT",
            "sleep-proxy" => "Sleep proxy",
            _ => RemoteText.Clean(service, 32),
        };
    }

    // A header of an SSDP reply (an HTTP response over UDP); the names come in any case.
    internal static string? Header(string text, string name)
    {
        foreach (string line in text.Split('\n'))
        {
            if (line.Length <= name.Length || line[name.Length] != ':' || !line.StartsWith(name, StringComparison.OrdinalIgnoreCase)) continue;
            return RemoteText.Clean(line[(name.Length + 1)..].Trim(), 200);
        }
        return null;
    }

    // The text of the first <tag>…</tag>, with the five XML entities read; nothing else of XML is honoured.
    internal static string Element(string xml, string tag)
    {
        int start = xml.IndexOf("<" + tag + ">", StringComparison.OrdinalIgnoreCase);
        if (start < 0) return string.Empty;
        start += tag.Length + 2;
        int end = xml.IndexOf("</" + tag + ">", start, StringComparison.OrdinalIgnoreCase);
        if (end < 0 || end - start > 256) return string.Empty;
        string value = xml[start..end].Replace("&amp;", "&").Replace("&lt;", "<").Replace("&gt;", ">").Replace("&quot;", "\"").Replace("&apos;", "'");
        return RemoteText.Clean(value.Trim(), 80);
    }

    // NBSTAT answer: [header 12][name: 34 bytes, or a 2-byte pointer][type 2][class 2][ttl 4][rdlength 2][count 1]
    // [count × (15-char name, suffix, 2 flag bytes)]: the workstation name and the workgroup.
    internal static (string Host, string Group) Nbstat(ReadOnlySpan<byte> r)
    {
        string host = string.Empty, group = string.Empty;
        if (r.Length < 13) return (host, group);
        int p = 12;
        p += (r[p] & 0xC0) == 0xC0 ? 2 : r[p] + 2;
        p += 10;
        if (p >= r.Length) return (host, group);
        int count = r[p++];
        for (int i = 0; i < count && p + 18 <= r.Length; i++, p += 18)
        {
            if (r[p + 15] != 0x00) continue;   // suffix 00: the workstation service
            string name = Encoding.ASCII.GetString(r.Slice(p, 15)).TrimEnd(' ', '\0');
            bool isGroup = (r[p + 16] & 0x80) != 0;
            if (isGroup) { if (group.Length == 0) group = name; }
            else if (host.Length == 0) host = name;
        }
        return (RemoteText.Clean(host, 32), RemoteText.Clean(group, 32));
    }
}
