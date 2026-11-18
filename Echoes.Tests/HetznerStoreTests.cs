using System.Text;
using System.Text.Json.Nodes;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Tests;

/// <summary>
/// Where the Hetzner tool keeps its projects (sealed with the device key, in the test folder's profile), how a backup
/// restore brings them in (marked restored, proxies off), and the checks on what a user types for firewall rules and
/// record sets.
/// </summary>
[Collection(HetznerCollection.Name)]
public sealed class HetznerStoreTests
{
    private const string Token = "hzStoreTestToken0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH";

    private sealed class MemorySettings : ISettings
    {
        public readonly Dictionary<string, string> Values = new();
        public string? GetSetting(string key) => Values.TryGetValue(key, out var v) ? v : null;
        public void SetSetting(string key, string? value) { if (value is null) Values.Remove(key); else Values[key] = value; }
        public void Remove(string key) => Values.Remove(key);
        public bool GetBool(string key, bool def = false) => Values.TryGetValue(key, out var v) ? v == "true" : def;
        public void SetBool(string key, bool value) => Values[key] = value ? "true" : "false";
        public int GetInt(string key, int def = 0) => Values.TryGetValue(key, out var v) && int.TryParse(v, out int i) ? i : def;
        public void SetMany(params (string key, string? value)[] items) { foreach (var (k, v) in items) SetSetting(k, v); }
    }

    private static HzProjectData Project(string name = "Prod") => new()
    {
        Id = HetznerStore.NewId(),
        Name = name,
        Token = Token,
        UseProxy = true,
        Proxy = "127.0.0.1:1080",
        ProxyUser = "me",
        ProxyPass = "proxySecret",
    };

    [Fact]
    public void Projects_are_stored_sealed_and_read_back()
    {
        var store = new MemorySettings();
        var p = Project();
        Assert.True(HetznerStore.Save(store, new[] { p }));
        string stored = store.GetSetting(HetznerStore.SettingKey)!;
        Assert.StartsWith("enc2:", stored, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, stored, StringComparison.Ordinal);
        Assert.DoesNotContain("proxySecret", stored, StringComparison.Ordinal);

        var back = Assert.Single(HetznerStore.Load(store, out var result));
        Assert.Equal(HetznerStore.LoadResult.Ok, result);
        Assert.Equal(p.Id, back.Id);
        Assert.Equal(Token, back.Token);
        Assert.Equal("proxySecret", back.ProxyPass);
        Assert.False(back.Restored);

        // the last one removed: nothing stays behind
        Assert.True(HetznerStore.Save(store, Array.Empty<HzProjectData>()));
        Assert.Null(store.GetSetting(HetznerStore.SettingKey));
    }

    [Fact]
    public void A_list_this_install_did_not_seal_is_treated_as_restored()
    {
        var store = new MemorySettings();
        store.SetSetting(HetznerStore.SettingKey, HetznerStore.ToJson(new[] { Project() }));   // plain JSON, as hand-made
        Assert.True(Assert.Single(HetznerStore.Load(store, out _)).Restored);

        // sealed with another install's key: it can never open here
        store.SetSetting(HetznerStore.SettingKey, "enc2:" + Convert.ToBase64String(new byte[64]));
        Assert.Empty(HetznerStore.Load(store, out var result));
        Assert.Equal(HetznerStore.LoadResult.Lost, result);
    }

    [Fact]
    public void Entries_without_a_usable_token_are_left_out()
    {
        string json = "{\"v\":1,\"projects\":[{\"id\":\"a\",\"name\":\"ok\",\"token\":\"" + Token + "\"},{\"id\":\"b\",\"name\":\"bad\",\"token\":\"has space\"},"
                      + "{\"id\":\"c\",\"name\":\"none\"},{\"id\":\"a\",\"name\":\"same id\",\"token\":\"" + Token + "x\"}]}";
        var list = HetznerStore.FromJson(json);
        Assert.Equal(new[] { "ok", "same id" }, list.Select(p => p.Name).ToArray());
        Assert.Equal(2, list.Select(p => p.Id).Distinct().Count());
    }

    [Fact]
    public void A_backups_projects_come_in_restored_with_their_proxy_off()
    {
        var disabled = new List<string>();
        string? rewritten = HetznerStore.DisarmJson(HetznerStore.ToJson(new[] { Project(), Project("Other") }), disabled);
        Assert.NotNull(rewritten);
        var list = HetznerStore.FromJson(rewritten!);
        Assert.Equal(2, list.Count);
        Assert.All(list, p => Assert.True(p.Restored));
        Assert.All(list, p => Assert.False(p.UseProxy));
        Assert.All(list, p => Assert.Equal(Token, p.Token));   // the token itself comes along (one tick resumes)
        Assert.Contains(HetznerStore.SettingKey, disabled);
        Assert.Contains(HetznerStore.SettingKey + "/proxy", disabled);
        Assert.Null(HetznerStore.DisarmJson("{\"nothing\":1}", disabled));
    }

    [Fact]
    public void A_backup_restore_disarms_the_projects_it_carries()
    {
        // as ExportForBackup carries a sealed value: "bak1:" + base64 of the plain JSON
        string carried = "bak1:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(HetznerStore.ToJson(new[] { Project() })));
        var backup = new JsonObject
        {
            ["settings"] = new JsonObject { [HetznerStore.SettingKey] = carried, ["hetzner.tab"] = "2" },
            ["knownHosts"] = new JsonObject(),
            ["history"] = new JsonObject(),
        }.ToJsonString();
        var report = ProfileService.Instance.ImportBackup(backup);
        Assert.Contains(HetznerStore.SettingKey, report.DisabledToggles);
        Assert.Contains(HetznerStore.SettingKey + "/proxy", report.DisabledToggles);

        string stored = ProfileService.Instance.GetSetting(HetznerStore.SettingKey)!;
        Assert.StartsWith("enc2:", stored, StringComparison.Ordinal);   // sealed again with this install's key
        var p = Assert.Single(HetznerStore.Load(ProfileService.Instance, out _));
        Assert.True(p.Restored);
        Assert.False(p.UseProxy);
        ProfileService.Instance.Remove(HetznerStore.SettingKey);
    }

    // ---------------------------------------------------------------- what the user types

    [Theory]
    [InlineData("22", "22")]
    [InlineData(" 8000-8100 ", "8000-8100")]
    [InlineData("ANY", "any")]
    [InlineData("0", null)]
    [InlineData("65536", null)]
    [InlineData("100-50", null)]
    [InlineData("80,443", null)]
    [InlineData("", null)]
    public void Ports_are_checked(string typed, string? expected) => Assert.Equal(expected, HetznerViewModel.NormalizePort(typed));

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7/32")]
    [InlineData("203.0.113.0/24", "203.0.113.0/24")]
    [InlineData("0.0.0.0/0", "0.0.0.0/0")]
    [InlineData("::/0", "::/0")]
    [InlineData("2001:DB8::1", "2001:db8::1/128")]
    [InlineData("2001:db8:ff00:42::/64", "2001:db8:ff00:42::/64")]
    [InlineData("203.0.113.7/24", null)]   // host bits set: not a network, not a single host
    [InlineData("203.0.113.0/33", null)]
    [InlineData("example.com", null)]
    [InlineData("fe80::1%eth0", null)]
    public void Addresses_become_cidr_blocks(string typed, string? expected)
        => Assert.Equal(expected, HetznerViewModel.NormalizeCidr(typed, out _));

    [Fact]
    public void Values_are_checked_for_their_type()
    {
        Assert.Equal(new[] { "203.0.113.7", "203.0.113.8" }, HetznerViewModel.ParseValues("A", "203.0.113.7\n 203.0.113.8 \n\n203.0.113.7", out _));
        Assert.Null(HetznerViewModel.ParseValues("A", "2001:db8::1", out string e1));
        Assert.Contains("IPv4", e1, StringComparison.Ordinal);
        Assert.Equal(new[] { "2001:db8::1" }, HetznerViewModel.ParseValues("AAAA", "2001:DB8:0::1", out _));
        Assert.Null(HetznerViewModel.ParseValues("CNAME", "a.example.com.\nb.example.com.", out _));
        Assert.Null(HetznerViewModel.ParseValues("MX", "  \n ", out _));
        Assert.Equal(new[] { "\"v=spf1 -all\"" }, HetznerViewModel.ParseValues("TXT", "v=spf1 -all", out _));
        Assert.Equal(new[] { "\"already quoted\"" }, HetznerViewModel.ParseValues("TXT", "\"already quoted\"", out _));
    }

    [Fact]
    public void Long_or_quoted_text_is_made_into_valid_txt_strings()
    {
        Assert.Equal("\"say \\\"hi\\\" \\\\o/\"", HetznerViewModel.QuoteTxt("say \"hi\" \\o/"));
        string longText = new string('a', 300);
        Assert.Equal("\"" + new string('a', 255) + "\" \"" + new string('a', 45) + "\"", HetznerViewModel.QuoteTxt(longText));
    }
}
