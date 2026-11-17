using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Echoes.Tests.Support;

/// <summary>
/// A DNS server on a loopback port, over UDP and TCP, for the queries Echoes sends by itself (the ones that leave
/// from a chosen interface). What it answers depends on the first label of the name:
/// <list type="bullet">
/// <item><c>nx.</c>: no such name (RCODE 3);</item>
/// <item><c>silent.</c>: nothing at all;</item>
/// <item><c>big.</c>: over UDP a truncated, empty answer; over TCP forty A records;</item>
/// <item>anything else: one A record 192.0.2.1 or one AAAA record 2001:db8::1 (other types: no records).</item>
/// </list>
/// </summary>
internal sealed class FakeDns : IDisposable
{
    private readonly Socket _udp;
    private readonly TcpListener _tcp;
    private readonly CancellationTokenSource _stop = new();
    private int _udpQueries, _tcpQueries;

    public IPAddress Address { get; }
    public int Port { get; }
    public int UdpQueries => Volatile.Read(ref _udpQueries);
    public int TcpQueries => Volatile.Read(ref _tcpQueries);
    /// <summary>Where the last UDP query came from.</summary>
    public IPEndPoint? LastUdpSource { get; private set; }

    public FakeDns(IPAddress address)
    {
        Address = address;
        // the same port number over both transports, as a real server has: a few tries in case the TCP one is taken
        for (int attempt = 0; ; attempt++)
        {
            var udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(address, 0));
            int port = ((IPEndPoint)udp.LocalEndPoint!).Port;
            var tcp = new TcpListener(address, port);
            try { tcp.Start(); }
            catch (SocketException) when (attempt < 20)
            {
                udp.Dispose();
                continue;
            }
            _udp = udp;
            _tcp = tcp;
            Port = port;
            break;
        }
        _ = Task.Run(UdpLoopAsync);
        _ = Task.Run(TcpLoopAsync);
    }

    private async Task UdpLoopAsync()
    {
        var buffer = new byte[2048];
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var r = await _udp.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(Address.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0), _stop.Token);
                Interlocked.Increment(ref _udpQueries);
                LastUdpSource = (IPEndPoint)r.RemoteEndPoint;
                if (Answer(buffer.AsSpan(0, r.ReceivedBytes), overTcp: false) is { } answer)
                    await _udp.SendToAsync(answer, SocketFlags.None, r.RemoteEndPoint, _stop.Token);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }

    private async Task TcpLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _tcp.AcceptTcpClientAsync(_stop.Token);
                _ = Task.Run(() => ServeAsync(client));
            }
        }
        catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var prefix = new byte[2];
                while (true)
                {
                    await stream.ReadExactlyAsync(prefix, _stop.Token);
                    var query = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
                    await stream.ReadExactlyAsync(query, _stop.Token);
                    Interlocked.Increment(ref _tcpQueries);
                    if (Answer(query, overTcp: true) is not { } answer) continue;
                    var framed = new byte[answer.Length + 2];
                    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)answer.Length);
                    answer.CopyTo(framed, 2);
                    await stream.WriteAsync(framed, _stop.Token);
                }
            }
            catch (Exception e) when (e is OperationCanceledException or IOException or SocketException or ObjectDisposedException or EndOfStreamException) { }
        }
    }

    // The answer to one query; null to stay silent (or for something that isn't a query).
    private static byte[]? Answer(ReadOnlySpan<byte> query, bool overTcp)
    {
        if (query.Length < 17 || (query[2] & 0x80) != 0) return null;
        // the question: labels up to the zero, then type and class
        int at = 12;
        string first = string.Empty;
        while (at < query.Length && query[at] != 0)
        {
            int length = query[at];
            if ((length & 0xC0) != 0 || at + 1 + length > query.Length) return null;
            if (first.Length == 0) first = System.Text.Encoding.ASCII.GetString(query.Slice(at + 1, length)).ToLowerInvariant();
            at += 1 + length;
        }
        if (at + 5 > query.Length) return null;
        int type = BinaryPrimitives.ReadUInt16BigEndian(query[(at + 1)..]);
        var question = query[12..(at + 5)].ToArray();

        if (first == "silent") return null;
        int rcode = first == "nx" ? 3 : 0;
        bool truncated = first == "big" && !overTcp;
        int count = rcode != 0 || truncated ? 0 : first == "big" ? 40 : type is 1 or 28 ? 1 : 0;

        var records = new List<byte[]>();
        for (int i = 0; i < count; i++)
        {
            byte[] data = type == 28
                ? IPAddress.Parse("2001:db8::1").GetAddressBytes()
                : new byte[] { 192, 0, 2, (byte)(first == "big" ? i + 1 : 1) };
            records.Add(Frames.DnsRecord((ushort)(type == 28 ? 28 : 1), data));
        }
        var header = new byte[12];
        query[..2].CopyTo(header);
        // a response, recursion desired as asked and available, truncated when it is
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), (ushort)(0x8080 | (query[2] & 0x01) << 8 | (truncated ? 0x0200 : 0) | rcode));
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), (ushort)records.Count);
        return Frames.Join(header, question, Frames.Join(records.ToArray()));
    }

    public void Dispose()
    {
        _stop.Cancel();
        _udp.Dispose();
        _tcp.Stop();
        _stop.Dispose();
    }
}
