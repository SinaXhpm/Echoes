using System.Net;
using Echoes.Helpers;

namespace Echoes.Tests;

/// <summary>The proxy server's rule boxes (Advanced): how allowed clients, allowed ports and blocked hosts are read,
/// what they match, and what is said about an entry that can't be read.</summary>
public class ProxyRulesTests
{
    private static ProxyRules Rules(string? clients = null, string? blocked = null, string? ports = null)
    {
        var rules = ProxyRules.Parse(clients, blocked, ports, out string? problem);
        Assert.Null(problem);
        return rules;
    }

    private static IPAddress Ip(string text) => IPAddress.Parse(text);

    // ------------------------------------------------------------------ nothing set

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  \r\n\t ")]
    public void Empty_boxes_are_no_rule(string? text)
    {
        var rules = Rules(text, text, text);
        Assert.True(rules.IsEmpty);
        Assert.False(rules.LimitsClients);
        Assert.False(rules.LimitsPorts);
        Assert.Equal(0, rules.BlockedCount);
        Assert.True(rules.ClientAllowed(Ip("203.0.113.9")));
        Assert.True(rules.ClientAllowed(null));
        Assert.True(rules.PortAllowed(25));
        Assert.False(rules.HostBlocked("example.com"));
        Assert.False(rules.AddressBlocked(Ip("203.0.113.9")));
    }

    [Fact]
    public void None_is_no_rule()
    {
        Assert.True(ProxyRules.None.IsEmpty);
        Assert.True(ProxyRules.None.ClientAllowed(Ip("::1")));
        Assert.True(ProxyRules.None.PortAllowed(1));
        Assert.False(ProxyRules.None.HostBlocked("anything.example"));
    }

    // ------------------------------------------------------------------ allowed clients

    [Theory]
    [InlineData("192.168.1.20", "192.168.1.20", true)]
    [InlineData("192.168.1.20", "192.168.1.21", false)]
    [InlineData("192.168.1.0/24", "192.168.1.255", true)]
    [InlineData("192.168.1.0/24", "192.168.2.0", false)]
    [InlineData("192.168.1.77/24", "192.168.1.3", true)]        // any address of the subnet names it
    [InlineData("10.0.0.0/8", "10.200.3.4", true)]
    [InlineData("0.0.0.0/0", "203.0.113.9", true)]
    [InlineData("192.168.1.10-192.168.1.50", "192.168.1.10", true)]
    [InlineData("192.168.1.10-192.168.1.50", "192.168.1.50", true)]
    [InlineData("192.168.1.10-192.168.1.50", "192.168.1.51", false)]
    [InlineData("192.168.1.10-50", "192.168.1.30", true)]
    [InlineData("192.168.1.10-50", "192.168.1.9", false)]
    [InlineData("192.168.1.*", "192.168.1.200", true)]
    [InlineData("192.168.1.*", "192.168.2.200", false)]
    [InlineData("192.168.*.*", "192.168.77.1", true)]
    [InlineData("10.*.*.*", "11.0.0.1", false)]
    [InlineData("192.168.*", "192.168.77.1", true)]              // the parts left out are stars too
    [InlineData("192.168.*", "192.169.0.1", false)]
    [InlineData("10.*", "10.200.3.4", true)]
    [InlineData("10.*.*", "10.1.2.3", true)]
    [InlineData("10.*", "11.0.0.1", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::5", true)]
    [InlineData("2001:db8::/32", "2001:db9::5", false)]
    [InlineData("2001:db8::7", "2001:db8::7", true)]
    [InlineData("[2001:db8::7]", "2001:db8::7", true)]
    [InlineData("fe80::1%12", "fe80::1", true)]                   // a zone isn't part of the address
    public void A_client_is_matched_against_the_list(string list, string client, bool allowed)
    {
        var rules = Rules(clients: list);
        Assert.True(rules.LimitsClients);
        Assert.Equal(allowed, rules.ClientAllowed(Ip(client)));
    }

    [Fact]
    public void Entries_are_separated_by_commas_spaces_semicolons_or_lines()
    {
        var rules = Rules(clients: "192.168.1.5, 192.168.1.6;192.168.1.7\r\n10.0.0.0/8\t172.16.0.9  ,, ");
        foreach (string a in new[] { "192.168.1.5", "192.168.1.6", "192.168.1.7", "10.9.9.9", "172.16.0.9" })
            Assert.True(rules.ClientAllowed(Ip(a)), a);
        Assert.False(rules.ClientAllowed(Ip("192.168.1.8")));
    }

    [Fact]
    public void An_ipv4_client_seen_as_an_ipv6_mapped_address_is_the_same_client()
    {
        var rules = Rules(clients: "192.168.1.0/24");
        Assert.True(rules.ClientAllowed(Ip("::ffff:192.168.1.20")));
        Assert.False(rules.ClientAllowed(Ip("::ffff:192.168.2.20")));
        // ...and an IPv4 list says nothing about IPv6 clients
        Assert.False(rules.ClientAllowed(Ip("2001:db8::1")));
    }

    [Fact]
    public void With_a_list_a_client_whose_address_is_unknown_is_not_on_it()
        => Assert.False(Rules(clients: "192.168.1.0/24").ClientAllowed(null));

    // ------------------------------------------------------------------ allowed ports

    [Fact]
    public void Only_listed_ports_and_ranges_may_be_reached()
    {
        var rules = Rules(ports: "80, 443 8000-8100");
        Assert.True(rules.LimitsPorts);
        foreach (int p in new[] { 80, 443, 8000, 8050, 8100 }) Assert.True(rules.PortAllowed(p), p.ToString());
        foreach (int p in new[] { 22, 25, 81, 7999, 8101, 65535 }) Assert.False(rules.PortAllowed(p), p.ToString());
    }

    // ------------------------------------------------------------------ blocked hosts

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "EXAMPLE.com", true)]
    [InlineData("example.com", "example.com.", true)]             // the root dot
    [InlineData("example.com", "www.example.com", true)]          // and everything under it
    [InlineData("example.com", "a.b.example.com", true)]
    [InlineData("example.com", "notexample.com", false)]          // a name, not its last letters
    [InlineData("example.com", "example.com.evil.net", false)]
    [InlineData("example.com", "example.org", false)]
    [InlineData(".example.com", "www.example.com", true)]
    [InlineData(".example.com", "example.com", true)]
    [InlineData("*.example.com", "www.example.com", true)]        // only what is under it
    [InlineData("*.example.com", "a.b.example.com", true)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("ads*.example.net", "ads.example.net", true)]
    [InlineData("ads*.example.net", "ads12.example.net", true)]
    [InlineData("ads*.example.net", "www.ads1.example.net", false)]
    [InlineData("*tracker*", "my.tracker.example", true)]
    [InlineData("*tracker*", "example.com", false)]
    [InlineData("Example.COM", "www.example.com", true)]
    [InlineData("https://example.com/some/page?x=1", "example.com", true)]   // a pasted URL is its host
    [InlineData("http://user@example.com:8080/", "www.example.com", true)]
    [InlineData("example.com:443", "example.com", true)]
    public void A_host_name_is_matched_against_the_blocked_list(string list, string host, bool blocked)
        => Assert.Equal(blocked, Rules(blocked: list).HostBlocked(host));

    [Fact]
    public void Blocked_addresses_and_subnets_are_matched_as_addresses()
    {
        var rules = Rules(blocked: "203.0.113.0/24, 198.51.100.7, 2001:db8::/32, example.com");
        Assert.Equal(4, rules.BlockedCount);
        Assert.True(rules.AddressBlocked(Ip("203.0.113.200")));
        Assert.True(rules.AddressBlocked(Ip("198.51.100.7")));
        Assert.True(rules.AddressBlocked(Ip("2001:db8:5::1")));
        Assert.True(rules.AddressBlocked(Ip("::ffff:203.0.113.1")));
        Assert.False(rules.AddressBlocked(Ip("198.51.100.8")));
        Assert.False(rules.AddressBlocked(Ip("192.0.2.1")));
        // names and addresses don't mix: an address is never looked up among the names
        Assert.False(rules.HostBlocked("203.0.113.200"));
        Assert.True(rules.HostBlocked("example.com"));
    }

    [Fact]
    public void A_short_address_wildcard_blocks_that_range_of_addresses()
    {
        // "192.168.*" and "10.*" as people write them: address ranges, not name patterns that no address would match
        var rules = Rules(blocked: "192.168.*, 10.*, ads*.example.net");
        Assert.True(rules.BlocksAddresses);
        Assert.Equal(3, rules.BlockedCount);
        Assert.True(rules.AddressBlocked(Ip("192.168.1.5")));
        Assert.True(rules.AddressBlocked(Ip("10.20.30.40")));
        Assert.True(rules.AddressBlocked(Ip("::ffff:192.168.0.1")));
        Assert.False(rules.AddressBlocked(Ip("192.169.1.5")));
        Assert.False(rules.AddressBlocked(Ip("11.0.0.1")));
        Assert.False(rules.HostBlocked("192.168.1.5"));
        Assert.True(rules.HostBlocked("ads1.example.net"));
    }

    [Fact]
    public void A_name_in_another_script_asked_for_as_it_is_meets_its_ascii_entry()
    {
        // the block is on the xn-- form; a client asking for the name in its own script must not get past it (it goes
        // on to an upstream proxy in that xn-- form)
        var rules = Rules(blocked: "xn--bcher-kva.example");
        Assert.True(rules.HostBlocked("bücher.example"));
        Assert.True(rules.HostBlocked("www.bücher.example."));
        Assert.False(rules.HostBlocked("buecher.example"));
    }

    [Fact]
    public void A_name_in_another_script_is_matched_in_its_ascii_form()
    {
        var rules = ProxyRules.Parse(null, "bücher.example", null, out string? problem);
        // (where this system can't convert such a name, the entry is refused with a message instead: never half-read)
        if (problem is not null)
        {
            Assert.Contains("Blocked hosts", problem);
            return;
        }
        Assert.True(rules.HostBlocked("xn--bcher-kva.example"));
        Assert.True(rules.HostBlocked("www.xn--bcher-kva.example"));
    }

    [Theory]
    [InlineData("*", "", true)]
    [InlineData("*", "anything", true)]
    [InlineData("a*c", "ac", true)]
    [InlineData("a*c", "abbbc", true)]
    [InlineData("a*c", "abcd", false)]
    [InlineData("a*b*c", "a-x-b-y-c", true)]
    [InlineData("a*b*c", "a-x-c", false)]
    [InlineData("**a", "bca", true)]
    [InlineData("abc", "abc", true)]
    [InlineData("abc", "abcd", false)]
    [InlineData("", "", true)]
    [InlineData("", "a", false)]
    public void Wildcards_match_any_run_of_characters(string pattern, string text, bool matches)
        => Assert.Equal(matches, ProxyRules.Matches(pattern, text));

    // ------------------------------------------------------------------ what can't be read

    [Theory]
    [InlineData("192.168.1")]                 // not four parts
    [InlineData("192.168.1.256")]
    [InlineData("192.168.1.0/33")]
    [InlineData("192.168.1.0/")]
    [InlineData("192.168.1.50-192.168.1.10")] // backwards
    [InlineData("192.168.1.10-")]
    [InlineData("192.*.1.1")]                 // the stars must be the last parts
    [InlineData("*.*.*.*")]
    [InlineData("192.168.1.5.*")]             // more than four parts
    [InlineData("2001:db8::/129")]
    [InlineData("my-phone")]                  // a name: clients are addresses
    [InlineData("0x7f.0.0.1")]
    public void A_client_entry_that_isnt_an_address_is_named_in_the_problem(string entry)
    {
        ProxyRules.Parse("192.168.1.5 " + entry, null, null, out string? problem);
        Assert.NotNull(problem);
        Assert.StartsWith("Allowed clients:", problem);
        Assert.Contains(entry, problem);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("http")]
    [InlineData("90-80")]
    [InlineData("80-")]
    [InlineData("-80")]
    [InlineData("8o")]
    public void A_port_entry_that_isnt_a_port_is_named_in_the_problem(string entry)
    {
        ProxyRules.Parse(null, null, "443 " + entry, out string? problem);
        Assert.NotNull(problem);
        Assert.StartsWith("Allowed ports:", problem);
        Assert.Contains(entry, problem);
    }

    [Theory]
    [InlineData("192.168.1")]                 // a mistyped address, not a name
    [InlineData("192.*.1.*")]                 // an address wildcard whose stars aren't the last parts, not a name pattern
    [InlineData("*.168.1.1")]
    [InlineData("192.168.1.5.*")]
    [InlineData("exa mple")]                  // (two entries, both fine)
    [InlineData("exam!ple.com")]
    [InlineData("example..com")]
    [InlineData("a:b:c")]
    public void A_blocked_entry_that_isnt_a_host_is_named_in_the_problem(string entry)
    {
        ProxyRules.Parse(null, entry, null, out string? problem);
        if (entry.Contains(' ')) { Assert.Null(problem); return; }
        Assert.NotNull(problem);
        Assert.StartsWith("Blocked hosts:", problem);
    }

    [Fact]
    public void A_long_entry_is_cut_in_the_problem()
    {
        string entry = new string('x', 300) + "!";
        ProxyRules.Parse(null, entry, null, out string? problem);
        Assert.NotNull(problem);
        Assert.True(problem!.Length < 160, problem);
        Assert.Contains("…", problem);
    }

    [Fact]
    public void More_entries_than_the_limit_is_a_problem_not_a_slow_proxy()
    {
        string many = string.Join(' ', Enumerable.Range(0, ProxyRules.MaxEntries + 1).Select(i => $"10.{i / 65536}.{i / 256 % 256}.{i % 256}"));
        ProxyRules.Parse(many, null, null, out string? problem);
        Assert.NotNull(problem);
        Assert.Contains(ProxyRules.MaxEntries.ToString(), problem);

        string fits = string.Join(' ', Enumerable.Range(0, ProxyRules.MaxEntries).Select(i => $"10.{i / 65536}.{i / 256 % 256}.{i % 256}"));
        Assert.True(Rules(clients: fits).ClientAllowed(Ip("10.0.7.207")));
    }

    // ------------------------------------------------------------------ the log row

    [Fact]
    public void A_log_rows_tooltip_names_the_client_and_a_failures_reason()
    {
        Assert.Equal("client 192.168.1.20", new ProxyLogEntry { Client = "192.168.1.20" }.Tip);
        Assert.Equal("client 192.168.1.20\nWi-Fi isn't connected.", new ProxyLogEntry { Client = "192.168.1.20", Detail = "Wi-Fi isn't connected." }.Tip);
    }
}
