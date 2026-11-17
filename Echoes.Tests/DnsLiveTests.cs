using System.Net;
using DnsClient;
using Echoes.Helpers;
using Echoes.Tests.Support;

namespace Echoes.Tests;

/// <summary>DNS queries from a chosen interface: Echoes sends those itself (UDP, and TCP when an answer is cut
/// short), on a socket tied to the interface. A server on a loopback port answers them (<see cref="FakeDns"/>).</summary>
[Collection(Live.Collection)]
public class DnsLiveTests
{
    private static ResolverSpec Spec(FakeDns dns)
    {
        var spec = Assert.Single(ResolverSpec.ParseList($"127.0.0.1:{dns.Port}"));
        Assert.Equal(DnsTransport.Plain, spec.Transport);
        return spec;
    }

    private static string Why(DnsResult r) => $"answered: {r.Answered}, rcode {r.Rcode}, via \"{r.Via}\", error: {r.Error}";

    /// <summary>The test server and the usual way of asking (the DnsClient library, no interface): this is what the
    /// answers from an interface are compared with.</summary>
    [Fact]
    public async Task Without_an_interface_the_test_server_answers_the_usual_client()
    {
        using var dns = new FakeDns(IPAddress.Loopback);
        using var session = new DnsSession(Spec(dns), TimeSpan.FromSeconds(4));
        using var deadline = Live.Deadline(30);

        var a = await session.QueryAsync("host.test", QueryType.A, deadline.Token);
        Assert.True(a.Ok, Why(a));
        Assert.Equal("192.0.2.1", Assert.Single(a.OfType("A")).Value);
        var big = await session.QueryAsync("big.test", QueryType.A, deadline.Token);
        Assert.True(big.Ok, Why(big));
        Assert.Equal(40, big.AnswerCount);
        Assert.True((await session.QueryAsync("nx.test", QueryType.A, deadline.Token)).IsNxDomain);
    }

    [Fact]
    public async Task A_query_from_the_loopback_interface_is_sent_from_it_and_answered()
    {
        var lo = Live.LoopbackForSockets();
        using var dns = new FakeDns(IPAddress.Loopback);
        using var session = new DnsSession(Spec(dns), TimeSpan.FromSeconds(4), lo);
        using var deadline = Live.Deadline(30);

        var a = await session.QueryAsync("host.test", QueryType.A, deadline.Token);
        Assert.True(a.Ok, Why(a));
        Assert.Equal("192.0.2.1", Assert.Single(a.OfType("A")).Value);
        Assert.Equal(1, a.AnswerCount);
        Assert.True(a.RttMs >= 0);
        Assert.True(dns.UdpQueries >= 1);
        Assert.Equal(0, dns.TcpQueries);
        Assert.Equal(IPAddress.Loopback, dns.LastUdpSource!.Address);

        var aaaa = await session.QueryAsync("host.test", QueryType.AAAA, deadline.Token);
        Assert.True(aaaa.Ok, Why(aaaa));
        Assert.Equal(IPAddress.Parse("2001:db8::1"), IPAddress.Parse(Assert.Single(aaaa.OfType("AAAA")).Value));

        // a name that doesn't exist is an answer, not a failure
        var nx = await session.QueryAsync("nx.test", QueryType.A, deadline.Token);
        Assert.True(nx.Answered, Why(nx));
        Assert.True(nx.IsNxDomain);
        Assert.Null(nx.Error);

        // a type the server has nothing for: answered, with no records
        var txt = await session.QueryAsync("host.test", QueryType.TXT, deadline.Token);
        Assert.True(txt.Ok, Why(txt));
        Assert.Empty(txt.Answers);
    }

    [Fact]
    public async Task A_truncated_answer_is_asked_again_over_tcp_from_the_same_interface()
    {
        var lo = Live.LoopbackForSockets();
        using var dns = new FakeDns(IPAddress.Loopback);
        using var session = new DnsSession(Spec(dns), TimeSpan.FromSeconds(4), lo);
        using var deadline = Live.Deadline(30);

        var big = await session.QueryAsync("big.test", QueryType.A, deadline.Token);
        Assert.True(big.Ok, Why(big));
        Assert.Equal(40, big.AnswerCount);
        Assert.Equal(40, big.OfType("A").Select(r => r.Value).Distinct().Count());
        Assert.True(dns.TcpQueries >= 1, "the truncated answer wasn't asked again over TCP");
    }

    [Fact]
    public async Task A_server_that_stays_silent_is_a_timeout_in_words()
    {
        var lo = Live.Loopback();
        using var dns = new FakeDns(IPAddress.Loopback);
        using var session = new DnsSession(Spec(dns), TimeSpan.FromSeconds(1), lo);
        using var deadline = Live.Deadline(30);

        var r = await session.QueryAsync("silent.test", QueryType.A, deadline.Token);
        Assert.False(r.Answered);
        Assert.False(string.IsNullOrWhiteSpace(r.Error));
        Assert.False(string.IsNullOrWhiteSpace(r.ShortError));
        Assert.True(dns.UdpQueries >= 1);
    }

    [Fact]
    public async Task A_port_nothing_listens_on_is_a_failure_in_words()
    {
        var lo = Live.Loopback();
        int port;
        using (var free = Live.UdpListener(IPAddress.Loopback)) port = ((IPEndPoint)free.LocalEndPoint!).Port;
        using var session = new DnsSession(Assert.Single(ResolverSpec.ParseList($"127.0.0.1:{port}")), TimeSpan.FromSeconds(1), lo);
        using var deadline = Live.Deadline(30);

        var r = await session.QueryAsync("host.test", QueryType.A, deadline.Token);
        Assert.False(r.Answered);
        Assert.False(string.IsNullOrWhiteSpace(r.Error));
    }

    [Fact]
    public async Task System_from_an_interface_that_was_given_no_dns_servers_says_so()
    {
        var bare = Live.Loopback() with { DnsServers = Array.Empty<IPAddress>() };
        using var session = new DnsSession(Assert.Single(ResolverSpec.ParseList("system")), TimeSpan.FromSeconds(2), bare);
        using var deadline = Live.Deadline();

        var r = await session.QueryAsync("host.test", QueryType.A, deadline.Token);
        Assert.False(r.Answered);
        Assert.Contains("has no DNS servers of its own", r.Error);
        Assert.Contains(bare.Name, r.Error);

        // ...and where the system's only DNS server is a program on this computer (Linux's 127.0.0.53), that is the reason given
        var stub = bare with { DnsIsLocalOnly = true };
        using var other = new DnsSession(Assert.Single(ResolverSpec.ParseList("system")), TimeSpan.FromSeconds(2), stub);
        r = await other.QueryAsync("host.test", QueryType.A, deadline.Token);
        Assert.False(r.Answered);
        Assert.Contains("a program on this computer", r.Error);
        Assert.Contains(stub.Name, r.Error);
    }

    [Fact]
    public async Task A_server_of_a_kind_the_interface_has_no_address_for_is_not_asked()
    {
        var v4Only = Live.Loopback() with { V6 = null, V6Link = null };
        using var session = new DnsSession(Assert.Single(ResolverSpec.ParseList("[2001:db8::53]:5300")), TimeSpan.FromSeconds(2), v4Only);
        using var deadline = Live.Deadline();

        var r = await session.QueryAsync("host.test", QueryType.A, deadline.Token);
        Assert.False(r.Answered);
        Assert.Contains("has no IPv6 address", r.Error);
    }
}
