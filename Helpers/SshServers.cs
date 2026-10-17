using CommunityToolkit.Mvvm.ComponentModel;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;

namespace Echoes.Helpers;

/// <summary>One port forward as configured (not its live state): -L local port → host:port via the server, or
/// -R server port → host:port reached from this device.</summary>
public sealed record SshForwardSpec(bool Remote, string BindHost, int BindPort, string TargetHost, int TargetPort)
{
    public string Flag => Remote ? "-R" : "-L";

    public JsonObject ToJson() => new()
    {
        ["k"] = Remote ? "R" : "L",
        ["bh"] = BindHost,
        ["bp"] = BindPort,
        ["th"] = TargetHost,
        ["tp"] = TargetPort,
    };

    public static SshForwardSpec? FromJson(JsonNode? n)
    {
        if (n is not JsonObject o) return null;
        bool remote = SshServerStore.Str(o["k"]) == "R";
        string bh = SshServerStore.Str(o["bh"]);
        string th = SshServerStore.Str(o["th"]);
        int bp = SshServerStore.Int(o["bp"]), tp = SshServerStore.Int(o["tp"]);
        if (th.Length == 0 || bp is < 0 or > 65535 || tp is < 1 or > 65535 || (remote && bp == 0)) return null;
        return new SshForwardSpec(remote, bh.Length == 0 ? "127.0.0.1" : bh, bp, th, tp);
    }

    public static JsonArray ToJson(IEnumerable<SshForwardSpec> specs) => new(specs.Select(s => (JsonNode)s.ToJson()).ToArray());

    public static List<SshForwardSpec> ListFromJson(JsonNode? n)
    {
        var list = new List<SshForwardSpec>();
        if (n is JsonArray arr)
            foreach (var item in arr)
                if (FromJson(item) is { } s && list.Count < SshServerStore.MaxForwards) list.Add(s);
        return list;
    }
}

/// <summary>
/// A saved server. Everything but the secrets is a plain profile setting ("ssh.servers"); the password and the key
/// passphrase are each a SEPARATE profile setting sealed with <see cref="SecretProtector"/> ("ssh.srv.&lt;id&gt;.pw" /
/// ".kp"), so they are never stored in plain text, and a backup carries / re-seals them like every other secret.
/// </summary>
public sealed partial class SshServerEntry : ObservableObject
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];

    [ObservableProperty] private string _name = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Detail))] private string _host = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Detail))] private int _port = 22;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(Detail))] private string _user = string.Empty;
    public string KeyPath { get; set; } = string.Empty;
    public bool UseProxy { get; set; }
    public string ProxyHost { get; set; } = "127.0.0.1";
    public int ProxyPort { get; set; } = 1080;
    public bool Tunnel { get; set; }
    public string TunnelHost { get; set; } = "127.0.0.1";
    public int TunnelPort { get; set; } = 8080;
    public List<SshForwardSpec> Forwards { get; set; } = new();

    /// <summary>"user@host:port" under the name in the picker.</summary>
    public string Detail => Port == 22 ? $"{User}@{Host}" : $"{User}@{SshText.Endpoint(Host, Port)}";

    public override string ToString() => Name;
}

/// <summary>Load / save of the saved servers and their sealed secrets. UI thread (ProfileService writes behind).</summary>
public static class SshServerStore
{
    public const string ListKey = "ssh.servers";
    public const int MaxServers = 200;
    public const int MaxForwards = 32;

    public static string PasswordKey(string id) => $"ssh.srv.{id}.pw";
    public static string PassphraseKey(string id) => $"ssh.srv.{id}.kp";

    internal static string Str(JsonNode? n) => n is JsonValue v && v.TryGetValue(out string? s) ? s : string.Empty;

    internal static int Int(JsonNode? n)
    {
        if (n is not JsonValue v) return -1;
        if (v.TryGetValue(out int i)) return i;
        return v.TryGetValue(out string? s) && int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out i) ? i : -1;
    }

    private static bool Bool(JsonNode? n) => n is JsonValue v && v.TryGetValue(out bool b) && b;

    public static List<SshServerEntry> Load()
    {
        var list = new List<SshServerEntry>();
        string raw = ProfileService.Instance.GetSetting(ListKey) ?? string.Empty;
        if (raw.Length == 0) return list;
        JsonNode? root;
        try { root = JsonNode.Parse(raw); }
        catch (Exception) { return list; }
        if (root is not JsonArray arr) return list;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var n in arr)
        {
            if (n is not JsonObject o || list.Count >= MaxServers) continue;
            string id = Str(o["id"]);
            string host = Str(o["host"]);
            if (id.Length == 0 || host.Length == 0 || !IsSafeId(id) || !ids.Add(id)) continue;
            int port = Int(o["port"]);
            var e = new SshServerEntry
            {
                Id = id,
                Name = Str(o["name"]) is { Length: > 0 } nm ? nm : host,
                Host = host,
                Port = port is >= 1 and <= 65535 ? port : 22,
                User = Str(o["user"]),
                KeyPath = Str(o["key"]),
            };
            if (o["proxy"] is JsonObject p)
            {
                e.UseProxy = Bool(p["on"]);
                e.ProxyHost = Str(p["host"]) is { Length: > 0 } ph ? ph : "127.0.0.1";
                e.ProxyPort = Int(p["port"]) is >= 1 and <= 65535 and var pp ? pp : 1080;
            }
            if (o["tunnel"] is JsonObject t)
            {
                e.Tunnel = Bool(t["on"]);
                e.TunnelHost = Str(t["host"]) is { Length: > 0 } th ? th : "127.0.0.1";
                e.TunnelPort = Int(t["port"]) is >= 0 and <= 65535 and var tp ? tp : 8080;
            }
            e.Forwards = SshForwardSpec.ListFromJson(o["fwd"]);
            list.Add(e);
        }
        return list;
    }

    // Ids become part of a profile key: keep them to what this app generates.
    private static bool IsSafeId(string id) => id.Length <= 40 && id.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    /// <summary>The list without secrets, as JSON.</summary>
    public static string Serialize(IEnumerable<SshServerEntry> all)
    {
        var arr = new JsonArray();
        foreach (var e in all)
            // Cast to JsonNode: the non-generic Add(JsonNode?) is AOT-safe; the generic Add<T> needs runtime codegen.
            arr.Add((JsonNode)new JsonObject
            {
                ["id"] = e.Id,
                ["name"] = e.Name,
                ["host"] = e.Host,
                ["port"] = e.Port,
                ["user"] = e.User,
                ["key"] = e.KeyPath,
                ["proxy"] = new JsonObject { ["on"] = e.UseProxy, ["host"] = e.ProxyHost, ["port"] = e.ProxyPort },
                ["tunnel"] = new JsonObject { ["on"] = e.Tunnel, ["host"] = e.TunnelHost, ["port"] = e.TunnelPort },
                ["fwd"] = SshForwardSpec.ToJson(e.Forwards),
            });
        return arr.ToJsonString();
    }

    public static void SaveList(IEnumerable<SshServerEntry> all)
        => ProfileService.Instance.SetSetting(ListKey, Serialize(all));

    /// <summary>The stored (sealed) secrets of one server, as they are on disk.</summary>
    public static (string Password, string Passphrase) RawSecrets(string id)
    {
        var ps = ProfileService.Instance;
        return (ps.GetSetting(PasswordKey(id)) ?? string.Empty, ps.GetSetting(PassphraseKey(id)) ?? string.Empty);
    }

    /// <summary>Opened secrets. A sealed value that doesn't open (no key file this run, another machine's profile)
    /// reads as empty and is reported, so a later save can keep the stored value instead of overwriting it.</summary>
    public static (string Password, string Passphrase, bool PasswordUnreadable, bool PassphraseUnreadable) OpenSecrets(string id)
    {
        var (rawPw, rawPp) = RawSecrets(id);
        string pw = rawPw.Length == 0 ? string.Empty : SecretProtector.Unprotect(rawPw);
        string pp = rawPp.Length == 0 ? string.Empty : SecretProtector.Unprotect(rawPp);
        // A legacy plaintext value (never written by this code, but hand edits happen) is re-sealed on the next save.
        return (pw, pp, rawPw.Length > 0 && pw.Length == 0, rawPp.Length > 0 && pp.Length == 0);
    }

    /// <summary>Seals and stores the secrets of one server; null = keep what is stored. Empty removes it.</summary>
    public static void SaveSecrets(string id, string? password, string? passphrase)
    {
        var items = new List<(string, string?)>(2);
        if (password is not null) items.Add((PasswordKey(id), password.Length == 0 ? string.Empty : SecretProtector.Protect(password)));
        if (passphrase is not null) items.Add((PassphraseKey(id), passphrase.Length == 0 ? string.Empty : SecretProtector.Protect(passphrase)));
        if (items.Count > 0) ProfileService.Instance.SetMany(items.ToArray());
        // An emptied secret leaves no key behind.
        if (password is { Length: 0 }) ProfileService.Instance.Remove(PasswordKey(id));
        if (passphrase is { Length: 0 }) ProfileService.Instance.Remove(PassphraseKey(id));
    }

    public static void DeleteSecrets(string id)
    {
        ProfileService.Instance.Remove(PasswordKey(id));
        ProfileService.Instance.Remove(PassphraseKey(id));
    }
}
