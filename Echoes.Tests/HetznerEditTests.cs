using System.Text.Json.Nodes;
using Echoes.Helpers;
using Echoes.Tests.Support;
using Echoes.ViewModels;

namespace Echoes.Tests;

/// <summary>
/// What a save of the Hetzner tool sends, without its screens: a firewall draft put on rules that changed elsewhere,
/// record set values and comments written back as Hetzner had them, the check that a record set is still as the editor
/// saw it, strict IPv4 input, and lists that repeat an item.
/// </summary>
[Collection(HetznerCollection.Name)]
public sealed class HetznerEditTests
{
    private static CancellationToken Test => TestContext.Current.CancellationToken;

    private static HzRule In(string port, string ip, string description = "")
        => new("in", "tcp", port, new[] { ip }, description);

    // ---------------------------------------------------------------- firewall rules changed elsewhere

    [Fact]
    public void A_rule_removed_elsewhere_doesnt_come_back_with_an_unrelated_change()
    {
        // loaded: SSH from anywhere and HTTP; a colleague then removes SSH in the Console
        var ssh = In("22", "0.0.0.0/0", "SSH from anywhere");
        var http = In("80", "0.0.0.0/0");
        var loaded = new[] { ssh, http };
        var current = new[] { http };
        // the user, unaware, adds HTTPS to the draft made on what was loaded
        var https = In("443", "0.0.0.0/0", "HTTPS");
        var draft = new[] { ssh, http, https };

        var rebase = HetznerViewModel.RebaseRules(loaded, draft, current);
        Assert.True(rebase.Changed);   // nothing may be written before a new review
        Assert.DoesNotContain(rebase.Draft, r => r.SameAs(ssh));
        Assert.Contains(rebase.Draft, r => r.SameAs(https));
        Assert.Contains(rebase.Draft, r => r.SameAs(http));
        // the new review against what Hetzner has: only the user's own change
        var change = Assert.Single(HetznerViewModel.Diff(current, rebase.Draft));
        Assert.True(change.IsAdd);
        Assert.Contains("443", change.Text, StringComparison.Ordinal);
    }

    [Fact]
    public void Rules_unchanged_elsewhere_keep_the_draft_as_it_is()
    {
        var a = In("22", "198.51.100.7/32");
        var b = In("80", "0.0.0.0/0");
        var c = In("443", "0.0.0.0/0");
        var rebase = HetznerViewModel.RebaseRules(new[] { a, b }, new[] { a, c }, new[] { b, a });   // same rules, another order
        Assert.False(rebase.Changed);
        Assert.Equal(2, rebase.Draft.Count);
        Assert.Same(c, rebase.Draft[1]);
    }

    [Fact]
    public void Edits_are_put_on_the_current_rules_one_by_one()
    {
        var ssh = In("22", "198.51.100.7/32", "office");
        var http = In("80", "0.0.0.0/0");
        var dns = new HzRule("out", "udp", "53", new[] { "0.0.0.0/0" }, "DNS");
        var mail = In("25", "0.0.0.0/0", "mail");      // added elsewhere meanwhile
        var loaded = new[] { ssh, http, dns };
        var current = new[] { ssh, http, mail };        // DNS was removed elsewhere too

        // the user moved SSH to another address (a change = remove + add) and removed DNS as well
        var sshNew = In("22", "198.51.100.8/32", "office");
        var draft = new[] { sshNew, http };

        var rebase = HetznerViewModel.RebaseRules(loaded, draft, current);
        Assert.True(rebase.Changed);
        Assert.Equal(3, rebase.Draft.Count);
        Assert.Contains(rebase.Draft, r => r.SameAs(sshNew));
        Assert.Contains(rebase.Draft, r => r.SameAs(mail));   // the colleague's rule stays
        Assert.DoesNotContain(rebase.Draft, r => r.SameAs(ssh));
        Assert.DoesNotContain(rebase.Draft, r => r.SameAs(dns));
        // a rule both added appears once
        var both = HetznerViewModel.RebaseRules(new[] { http }, new[] { http, mail }, new[] { http, mail, dns });
        Assert.Single(both.Draft, r => r.SameAs(mail));
    }

    [Fact]
    public void Rules_are_compared_as_a_set()
    {
        var a = In("22", "198.51.100.7/32");
        var b = In("80", "0.0.0.0/0");
        Assert.True(HetznerViewModel.SameRules(new[] { a, b }, new[] { b, a }));
        Assert.False(HetznerViewModel.SameRules(new[] { a, b }, new[] { a, a }));
        Assert.False(HetznerViewModel.SameRules(new[] { a }, new[] { a, b }));
        Assert.False(HetznerViewModel.SameRules(new[] { a }, new[] { In("22", "198.51.100.7/32", "now with a note") }));
    }

    [Fact]
    public void A_rule_this_build_cant_read_makes_the_firewall_read_only_here()
    {
        var fw = HzFirewall.From(JsonNode.Parse("""
            {"id":11,"name":"web","rules":[
              {"direction":"in","protocol":"tcp","port":"22","source_ips":["0.0.0.0/0"]},
              {"direction":"in","protocol":"sctp","port":"9","source_ips":["0.0.0.0/0"]}]}
            """), new Dictionary<long, string>());
        Assert.NotNull(fw);
        Assert.True(fw!.HasUnreadableRules);
        Assert.Single(fw.Rules);
    }

    [Fact]
    public void A_rule_goes_back_exactly_as_hetzner_had_it()
    {
        string description = new string('d', 250) + "\u0007bell";   // 255 characters, one a control character
        var rule = HzRule.From(JsonNode.Parse(new JsonObject
        {
            ["direction"] = "in", ["protocol"] = "tcp", ["port"] = "443",
            ["source_ips"] = new JsonArray { (JsonNode)JsonValue.Create("0.0.0.0/0")! },
            ["description"] = description,
        }.ToJsonString()));
        Assert.NotNull(rule);
        Assert.Equal(description, rule!.Description);
        Assert.Equal(description, rule.ToJson()["description"]!.GetValue<string>());
        Assert.DoesNotContain('\u0007', rule.DescriptionText);   // the screen gets a clean, clipped text
    }

    // ---------------------------------------------------------------- record sets

    private static HzRrset Set(params (string Value, string Comment)[] values)
    {
        var records = new JsonArray();
        foreach (var (v, c) in values) records.Add((JsonNode)new JsonObject { ["value"] = v, ["comment"] = c });
        return HzRrset.From(new JsonObject { ["name"] = "home", ["type"] = "A", ["ttl"] = 60, ["records"] = records,
                                             ["protection"] = new JsonObject { ["change"] = false } }, "example.com", 3600)!;
    }

    [Fact]
    public void A_single_values_comment_moves_to_its_new_value()
    {
        var old = Set(("203.0.113.1", "router at home"));
        var records = HetznerViewModel.RecordsToWrite(old, new[] { "203.0.113.2" });
        Assert.Equal("[{\"value\":\"203.0.113.2\",\"comment\":\"router at home\"}]", records.ToJsonString());
    }

    [Fact]
    public void Values_that_stay_keep_their_comments_and_new_ones_have_none()
    {
        var old = Set(("203.0.113.1", "a"), ("203.0.113.2", "b"));
        var records = HetznerViewModel.RecordsToWrite(old, new[] { "203.0.113.2", "203.0.113.3" });
        Assert.Equal("[{\"value\":\"203.0.113.2\",\"comment\":\"b\"},{\"value\":\"203.0.113.3\"}]", records.ToJsonString());
    }

    [Fact]
    public void A_long_comment_is_written_back_whole()
    {
        string comment = new string('c', 300) + "\u0001";   // longer than the screen shows, with a control character
        var old = Set(("203.0.113.1", comment));
        Assert.Equal(comment, old.Values[0].Comment);
        var records = HetznerViewModel.RecordsToWrite(old, new[] { "203.0.113.1", "203.0.113.9" });
        Assert.Equal(comment, records[0]!["comment"]!.GetValue<string>());
    }

    [Fact]
    public void A_set_changed_elsewhere_is_noticed()
    {
        var seen = Set(("203.0.113.1", "a"), ("203.0.113.2", ""));
        Assert.True(seen.SameAs(Set(("203.0.113.2", ""), ("203.0.113.1", "a"))));   // the order doesn't matter
        Assert.False(seen.SameAs(Set(("203.0.113.1", "a"))));
        Assert.False(seen.SameAs(Set(("203.0.113.1", "a"), ("203.0.113.3", ""))));
        Assert.False(seen.SameAs(Set(("203.0.113.1", "changed"), ("203.0.113.2", ""))));
        var otherTtl = HzRrset.From(JsonNode.Parse("""{"name":"home","type":"A","ttl":300,"records":[{"value":"203.0.113.1","comment":"a"},{"value":"203.0.113.2","comment":""}]}"""), "example.com", 3600)!;
        Assert.False(seen.SameAs(otherTtl));
    }

    [Fact]
    public void A_set_the_editor_cant_show_whole_isnt_editable()
    {
        var lineBreak = HzRrset.From(JsonNode.Parse("""{"name":"t","type":"TXT","records":[{"value":"\"one\"\n\"two\"","comment":""}]}"""), "example.com", 3600)!;
        Assert.True(lineBreak.Unreadable);
        Assert.False(lineBreak.IsEditable);

        var many = new JsonArray();
        for (int i = 0; i < HzRrset.MaxValues + 1; i++) many.Add((JsonNode)new JsonObject { ["value"] = $"10.0.{i / 256}.{i % 256}" });
        var big = HzRrset.From(new JsonObject { ["name"] = "big", ["type"] = "A", ["records"] = many }, "example.com", 3600)!;
        Assert.Equal(HzRrset.MaxValues + 1, big.Values.Count);   // nothing is dropped
        Assert.False(big.IsEditable);
    }

    // ---------------------------------------------------------------- input

    [Theory]
    [InlineData("203.0.113")]       // IPAddress.TryParse: 203.0.0.113
    [InlineData("22")]              // 0.0.0.22
    [InlineData("192.168.010.1")]   // octal: 192.168.8.1
    [InlineData("0x7f.0.0.1")]
    [InlineData("1.2.3.4.5")]
    public void An_ipv4_address_is_four_dotted_decimals(string typed)
    {
        Assert.Null(HetznerViewModel.ParseValues("A", typed, out _));
        Assert.Null(HetznerViewModel.NormalizeCidr(typed, out _));
        Assert.Null(HetznerViewModel.NormalizeCidr(typed + "/32", out _));
    }

    [Fact]
    public void Plain_addresses_still_pass()
    {
        Assert.Equal(new[] { "203.0.113.0" }, HetznerViewModel.ParseValues("A", "203.0.113.0", out _));
        Assert.Equal("10.0.0.0/8", HetznerViewModel.NormalizeCidr("10.0.0.0/8", out _));
        Assert.Equal("0.0.0.0/0", HetznerViewModel.NormalizeCidr("0.0.0.0/0", out _));
        Assert.Equal("2001:db8::/32", HetznerViewModel.NormalizeCidr("2001:DB8::/32", out _));
    }

    [Fact]
    public void A_repeated_id_keeps_the_last_item_read()
    {
        var items = new[] { (Id: 1L, Name: "a"), (Id: 2L, Name: "b"), (Id: 1L, Name: "a again") };
        var unique = HetznerViewModel.LastById(items, i => i.Id);
        Assert.Equal(new[] { "a again", "b" }, unique.Select(i => i.Name).ToArray());
    }

    // ---------------------------------------------------------------- a read-only token, as Hetzner spelled it before

    [Fact]
    public async Task The_older_read_only_code_is_taken_for_a_read_only_token_too()
    {
        string saved = HetznerApi.BaseUrl;
        try
        {
            using var mock = new MockHttp(_ => MockHttp.Response.Json("{\"error\":{\"code\":\"token_readonly\",\"message\":\"the token is read-only\"}}", 403));
            HetznerApi.BaseUrl = mock.Root + "/v1";
            using var api = HetznerApi.Create("hzEditTestToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ", null, null, null);
            var r = await api.PostAsync("/servers/1/actions/reboot", null, Test);
            Assert.True(r.ReadOnly);
            Assert.Contains("Security → API tokens", r.Error, StringComparison.Ordinal);
        }
        finally { HetznerApi.BaseUrl = saved; }
    }
}
