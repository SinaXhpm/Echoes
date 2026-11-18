using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;

namespace Echoes.ViewModels;

/// <summary>A saved Hetzner project in the picker. Its token stays in <see cref="Data"/> and is never bound to the UI.</summary>
public partial class HzProject : ObservableObject
{
    public HzProject(HzProjectData data)
    {
        Data = data;
        _name = data.Name;
        _restored = data.Restored;
        _readOnly = data.ReadOnly;
    }

    public HzProjectData Data { get; private set; }

    [ObservableProperty] private string _name;
    /// <summary>From a backup: dynamic DNS waits until the user confirms it.</summary>
    [ObservableProperty] private bool _restored;
    /// <summary>Hetzner said its token can only read.</summary>
    [ObservableProperty] private bool _readOnly;

    /// <summary>Take an edited copy (name, token, proxy) as the project's data.</summary>
    internal void Replace(HzProjectData data)
    {
        Data = data;
        Name = data.Name;
        Restored = data.Restored;
        ReadOnly = data.ReadOnly;
    }

    partial void OnRestoredChanged(bool value) => Data.Restored = value;
    partial void OnReadOnlyChanged(bool value) => Data.ReadOnly = value;

    public override string ToString() => Name;
}

/// <summary>A label and a value in a details list, copied with its button.</summary>
public sealed class HzField
{
    public HzField(string label, string value, bool mono = true, bool copy = true)
    {
        Label = label;
        Value = value;
        Mono = mono;
        CanCopy = copy && value.Length > 0;
    }

    public string Label { get; }
    public string Value { get; }
    public bool Mono { get; }
    public bool CanCopy { get; }
}

/// <summary>One cloud server: what the list shows and what its details need. Built from the API's server object, with
/// every string clipped (the answer is untrusted).</summary>
public partial class HzServer : ObservableObject
{
    public long Id { get; init; }
    public string Name { get; init; } = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText), nameof(IsRunning), nameof(IsOff), nameof(IsChanging), nameof(CanPowerOn), nameof(CanPowerOff))]
    private string _status = "unknown";
    public string TypeName { get; init; } = string.Empty;
    /// <summary>"2 vCPU · 4 GB · 40 GB".</summary>
    public string TypeText { get; init; } = string.Empty;
    public string Location { get; init; } = string.Empty;
    public string LocationCode { get; init; } = string.Empty;
    public string Ipv4 { get; init; } = string.Empty;
    public string Ipv4Ptr { get; init; } = string.Empty;
    public bool Ipv4Blocked { get; init; }
    /// <summary>The server's IPv6 network ("2001:db8:1::/64").</summary>
    public string Ipv6 { get; init; } = string.Empty;
    public IReadOnlyList<string> Ipv6Ptrs { get; init; } = Array.Empty<string>();
    public string Image { get; init; } = string.Empty;
    public IReadOnlyList<string> PrivateNets { get; init; } = Array.Empty<string>();
    public long? Outgoing { get; init; }
    public long? Ingoing { get; init; }
    public long? Included { get; init; }
    public bool ProtectDelete { get; init; }
    public bool ProtectRebuild { get; init; }
    public IReadOnlyList<string> Labels { get; init; } = Array.Empty<string>();
    public IReadOnlyList<(long Id, string Status)> Firewalls { get; init; } = Array.Empty<(long, string)>();
    public bool Rescue { get; init; }
    public bool Locked { get; init; }
    public string Created { get; init; } = string.Empty;

    public string StatusText => Status switch
    {
        "running" => "Running",
        "off" => "Off",
        "starting" => "Starting",
        "stopping" => "Stopping",
        "initializing" => "Initializing",
        "rebuilding" => "Rebuilding",
        "migrating" => "Migrating",
        "deleting" => "Deleting",
        _ => "Unknown",
    };

    public bool IsRunning => Status == "running";
    public bool IsOff => Status == "off";
    public bool IsChanging => !IsRunning && !IsOff;
    public bool CanPowerOn => !IsRunning;
    public bool CanPowerOff => !IsOff;

    public string Ipv4Text => Ipv4.Length > 0 ? Ipv4 : "no IPv4";
    public string Ipv6Text => Ipv6.Length > 0 ? Ipv6 : "no IPv6";
    public string ImageText => Image.Length > 0 ? Image : "no image";

    /// <summary>The address other tools get (Ping, SSH, WHOIS): the IPv4, else the IPv6 network's ::1 (the address
    /// Hetzner's images give the server by default).</summary>
    public string HostAddress
    {
        get
        {
            if (Ipv4.Length > 0) return Ipv4;
            int slash = Ipv6.IndexOf('/');
            string net = slash > 0 ? Ipv6[..slash] : Ipv6;
            if (System.Net.IPAddress.TryParse(net, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                byte[] b = ip.GetAddressBytes();
                b[15] |= 1;
                return new System.Net.IPAddress(b).ToString();
            }
            return string.Empty;
        }
    }

    public bool HasHost => HostAddress.Length > 0;

    public static HzServer? From(JsonNode? n)
    {
        if (n is not JsonObject o || CfJson.Long(o["id"]) is not long id || !HetznerApi.IsId(id)) return null;
        var type = o["server_type"];
        var loc = o["location"];
        var net = o["public_net"];
        var image = o["image"];

        var parts = new List<string>();
        if (Num(type?["cores"]) is { } cores) parts.Add($"{cores} vCPU");
        if (Num(type?["memory"]) is { } mem) parts.Add($"{mem} GB");
        if (Num(type?["disk"]) is { } disk) parts.Add($"{disk} GB");
        string city = Clip(CfJson.Str(loc?["city"]), 60), country = Clip(CfJson.Str(loc?["country"]), 8);
        string location = city.Length > 0 && country.Length > 0 ? $"{city}, {country}" : city.Length > 0 ? city : Clip(CfJson.Str(loc?["name"]), 40);

        string imageText = Clip(CfJson.Str(image?["description"]), 80);
        if (imageText.Length == 0) imageText = Clip(CfJson.Str(image?["name"]), 80);

        var ptr6 = new List<string>();
        if (net?["ipv6"]?["dns_ptr"] is JsonArray ptrs)
            foreach (var p in ptrs.Take(20))
            {
                string ip = Clip(CfJson.Str(p?["ip"]), 60), name = Clip(CfJson.Str(p?["dns_ptr"]), 253);
                if (ip.Length > 0 || name.Length > 0) ptr6.Add($"{ip} → {name}");
            }

        var priv = new List<string>();
        if (o["private_net"] is JsonArray nets)
            foreach (var p in nets.Take(20))
            {
                string ip = Clip(CfJson.Str(p?["ip"]), 60);
                long? netId = CfJson.Long(p?["network"]);
                if (ip.Length > 0) priv.Add(netId is { } nid ? $"{ip} (network {nid.ToString(CultureInfo.InvariantCulture)})" : ip);
            }

        var labels = new List<string>();
        if (o["labels"] is JsonObject lo)
            foreach (var kv in lo.Take(30))
            {
                string v = Clip(CfJson.Str(kv.Value), 80);
                labels.Add(v.Length > 0 ? $"{Clip(kv.Key, 80)}={v}" : Clip(kv.Key, 80));
            }

        var fws = new List<(long, string)>();
        if (net?["firewalls"] is JsonArray fwa)
            foreach (var f in fwa.Take(30))
                if (CfJson.Long(f?["id"]) is long fid && HetznerApi.IsId(fid))
                    fws.Add((fid, Clip(CfJson.Str(f?["status"]), 20)));

        string created = CfJson.Str(o["created"]);
        if (DateTimeOffset.TryParse(created, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var c))
            created = c.ToLocalTime().ToString("MMM d, yyyy", CultureInfo.InvariantCulture);
        else created = string.Empty;

        return new HzServer
        {
            Id = id,
            Name = Clip(CfJson.Str(o["name"]), 80),
            Status = Clip(CfJson.Str(o["status"]), 20),
            TypeName = Clip(CfJson.Str(type?["name"]), 30).ToUpperInvariant(),
            TypeText = string.Join(" · ", parts),
            Location = location,
            LocationCode = Clip(CfJson.Str(loc?["name"]), 20),
            Ipv4 = IpOnly(CfJson.Str(net?["ipv4"]?["ip"])),
            Ipv4Ptr = Clip(CfJson.Str(net?["ipv4"]?["dns_ptr"]), 253),
            Ipv4Blocked = CfJson.Bool(net?["ipv4"]?["blocked"]),
            Ipv6 = Clip(CfJson.Str(net?["ipv6"]?["ip"]), 60),
            Ipv6Ptrs = ptr6,
            Image = imageText,
            PrivateNets = priv,
            Outgoing = CfJson.Long(o["outgoing_traffic"]),
            Ingoing = CfJson.Long(o["ingoing_traffic"]),
            Included = CfJson.Long(o["included_traffic"]),
            ProtectDelete = CfJson.Bool(o["protection"]?["delete"]),
            ProtectRebuild = CfJson.Bool(o["protection"]?["rebuild"]),
            Labels = labels,
            Firewalls = fws,
            Rescue = CfJson.Bool(o["rescue_enabled"]),
            Locked = CfJson.Bool(o["locked"]),
            Created = created,
        };
    }

    // an address the answer gives must be one (it goes to other tools and the clipboard)
    private static string IpOnly(string s) => System.Net.IPAddress.TryParse(s.Trim(), out var ip) ? ip.ToString() : string.Empty;

    private static string? Num(JsonNode? n)
    {
        if (n is not JsonValue v || v.GetValueKind() != System.Text.Json.JsonValueKind.Number || !v.TryGetValue(out double d)
            || !double.IsFinite(d) || d < 0 || d > 1e7) return null;
        return d.ToString("0.##", CultureInfo.InvariantCulture);
    }

    internal static string Clip(string? s, int max) => HetznerApi.Clip(s, max);

    /// <summary>Bytes as "1.2 TB" / "340 GB" (decimal units, as Hetzner bills traffic).</summary>
    public static string Bytes(long b)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
        double v = b;
        int u = 0;
        while (v >= 1000 && u < units.Length - 1) { v /= 1000; u++; }
        return (u == 0 ? v.ToString("0", CultureInfo.InvariantCulture) : v.ToString(v < 10 ? "0.#" : "0", CultureInfo.InvariantCulture)) + " " + units[u];
    }

    public string TrafficText
    {
        get
        {
            if (Outgoing is null && Included is null) return "not reported yet";
            string used = Bytes(Math.Max(0, Outgoing ?? 0));
            string text = Included is long inc && inc > 0
                ? $"{used} of {Bytes(inc)} out ({Math.Round(100.0 * Math.Max(0, Outgoing ?? 0) / inc):0}%)"
                : $"{used} out";
            if (Ingoing is long inn) text += $" · {Bytes(Math.Max(0, inn))} in";
            return text;
        }
    }
}

/// <summary>
/// One firewall rule as the API has it. Its fields are kept exactly as Hetzner sent them, since a save sends every rule
/// back (set_rules replaces the list): a clipped description would come back changed. Only the texts for the screen
/// are clipped. Equality is by value (the change preview and the save's conflict check compare them).
/// </summary>
public sealed record HzRule(string Direction, string Protocol, string Port, IReadOnlyList<string> Ips, string Description)
{
    public bool IsIn => Direction == "in";
    public bool HasPort => Protocol is "tcp" or "udp";

    public static readonly string[] Protocols = { "tcp", "udp", "icmp", "esp", "gre" };

    public static HzRule? From(JsonNode? n)
    {
        if (n is not JsonObject o) return null;
        string dir = CfJson.Str(o["direction"]);
        string proto = CfJson.Str(o["protocol"]);
        if (dir is not ("in" or "out") || Array.IndexOf(Protocols, proto) < 0) return null;
        var ips = CfJson.StrList(dir == "in" ? o["source_ips"] : o["destination_ips"]);
        return new HzRule(dir, proto, CfJson.Str(o["port"]), ips, CfJson.Str(o["description"]));
    }

    public JsonObject ToJson()
    {
        var ips = new JsonArray();
        foreach (var ip in Ips) ips.Add((JsonNode)JsonValue.Create(ip)!);
        var o = new JsonObject
        {
            ["direction"] = Direction,
            ["protocol"] = Protocol,
        };
        if (IsIn) o["source_ips"] = ips;
        else o["destination_ips"] = ips;
        if (HasPort && Port.Length > 0) o["port"] = Port;
        if (Description.Length > 0) o["description"] = Description;
        return o;
    }

    public bool SameAs(HzRule other)
        => Direction == other.Direction && Protocol == other.Protocol && Port == other.Port && Description == other.Description
           && Ips.SequenceEqual(other.Ips);

    // ---- for the screen only (clipped: the answer is untrusted)
    public string PortText => HasPort ? (Port.Length > 0 ? HetznerApi.Clip(Port, 20) : "any") : "–";
    public string IpsText => Ips.Count == 0 ? "nowhere"
        : string.Join(", ", Ips.Take(30).Select(i => i is "0.0.0.0/0" or "::/0" ? "any " + (i.Contains(':') ? "IPv6" : "IPv4") : HetznerApi.Clip(i, 64)))
          + (Ips.Count > 30 ? $" and {Ips.Count - 30} more" : string.Empty);
    public string DescriptionText => HetznerApi.Clip(Description, 255);
    public string Summary => $"{(IsIn ? "In" : "Out")} {Protocol.ToUpperInvariant()} {PortText} {(IsIn ? "from" : "to")} {IpsText}";
}

/// <summary>A rule row in the firewall editor: the rule, and how it differs from what Hetzner has.</summary>
public partial class HzRuleRow : ObservableObject
{
    public HzRuleRow(HzRule rule, string change)
    {
        Rule = rule;
        Change = change;
    }

    public HzRule Rule { get; }
    /// <summary>"" (as saved), "new" or "changed".</summary>
    public string Change { get; }
    public bool IsNew => Change == "new";
    public bool IsChanged => Change == "changed";
    public bool HasChange => Change.Length > 0;
    public string ChangeText => IsNew ? "New" : IsChanged ? "Changed" : string.Empty;
    public string DirectionText => Rule.IsIn ? "IN" : "OUT";
    public bool IsIn => Rule.IsIn;
    public string ProtocolText => Rule.Protocol.ToUpperInvariant();
    public string PortText => Rule.PortText;
    public string IpsText => Rule.IpsText;
    public string Description => Rule.DescriptionText;
    public bool HasDescription => Rule.Description.Length > 0;
}

/// <summary>A line of the save preview: Added / Removed / Changed and the rule.</summary>
public sealed class HzRuleChange
{
    public HzRuleChange(string action, HzRule rule)
    {
        Action = action;
        Text = rule.Summary;
        Description = rule.DescriptionText;
    }

    public string Action { get; }
    public string Text { get; }
    public string Description { get; }
    public bool HasDescription => Description.Length > 0;
    public bool IsAdd => Action == "Add";
    public bool IsRemove => Action == "Remove";
}

/// <summary>A firewall: its saved rules and where it is applied.</summary>
public partial class HzFirewall : ObservableObject
{
    public long Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public IReadOnlyList<HzRule> Rules { get; set; } = Array.Empty<HzRule>();
    /// <summary>"server web-1", "label env=prod (3 servers)".</summary>
    public IReadOnlyList<string> AppliedTo { get; set; } = Array.Empty<string>();
    public IReadOnlyList<long> ServerIds { get; set; } = Array.Empty<long>();
    /// <summary>A rule this build can't read (an unknown protocol, say): a save would drop it, so the rules can't be
    /// edited here.</summary>
    public bool HasUnreadableRules { get; set; }

    public string RulesText
    {
        get
        {
            int inn = Rules.Count(r => r.IsIn), outn = Rules.Count - inn;
            return Rules.Count == 0 ? "no rules" : $"{inn} in · {outn} out";
        }
    }

    public string AppliedText => AppliedTo.Count == 0 ? "not applied" : AppliedTo.Count == 1 ? "applied to 1" : $"applied to {AppliedTo.Count}";
    public string AppliedList => AppliedTo.Count == 0 ? "Not applied to any server." : string.Join(", ", AppliedTo);

    internal void RaiseRules() => OnPropertyChanged(nameof(RulesText));

    /// <summary>Take what Hetzner has now (the same firewall read again), in place: the picker keeps its selection.</summary>
    internal void UpdateFrom(HzFirewall fresh)
    {
        Rules = fresh.Rules;
        AppliedTo = fresh.AppliedTo;
        ServerIds = fresh.ServerIds;
        HasUnreadableRules = fresh.HasUnreadableRules;
        OnPropertyChanged(nameof(RulesText));
        OnPropertyChanged(nameof(AppliedText));
        OnPropertyChanged(nameof(AppliedList));
    }

    public static HzFirewall? From(JsonNode? n, IReadOnlyDictionary<long, string> serverNames)
    {
        if (n is not JsonObject o || CfJson.Long(o["id"]) is not long id || !HetznerApi.IsId(id)) return null;
        var rules = new List<HzRule>();
        bool unreadable = false;
        if (o["rules"] is JsonArray ra)
            foreach (var r in ra)
            {
                if (HzRule.From(r) is { } rule) rules.Add(rule);
                else unreadable = true;
            }
        var applied = new List<string>();
        var servers = new List<long>();
        if (o["applied_to"] is JsonArray aa)
            foreach (var a in aa.Take(100))
            {
                string kind = CfJson.Str(a?["type"]);
                if (kind == "server" && CfJson.Long(a?["server"]?["id"]) is long sid)
                {
                    servers.Add(sid);
                    applied.Add(serverNames.TryGetValue(sid, out var sn) ? sn : "server " + sid.ToString(CultureInfo.InvariantCulture));
                }
                else if (kind == "label_selector")
                {
                    string sel = HetznerApi.Clip(CfJson.Str(a?["label_selector"]?["selector"]), 120);
                    int count = (a?["applied_to_resources"] as JsonArray)?.Count ?? 0;
                    applied.Add($"label {sel} ({count} server{(count == 1 ? "" : "s")})");
                }
            }
        return new HzFirewall
        {
            Id = id,
            Name = HetznerApi.Clip(CfJson.Str(o["name"]), 80),
            Rules = rules,
            AppliedTo = applied,
            ServerIds = servers,
            HasUnreadableRules = unreadable,
        };
    }
}

/// <summary>A DNS zone in the Cloud API.</summary>
public partial class HzZone : ObservableObject
{
    public long Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Mode { get; init; } = "primary";
    public int Ttl { get; init; }
    public string Status { get; init; } = string.Empty;
    public int RecordCount { get; init; }
    public string Delegation { get; init; } = "unknown";
    public IReadOnlyList<string> Assigned { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Delegated { get; init; } = Array.Empty<string>();
    public bool ProtectDelete { get; init; }

    public bool IsPrimary => Mode == "primary";
    public string StatusText => Status switch { "ok" => "Published", "updating" => "Updating", "error" => "Error", _ => "Unknown" };
    public bool IsOk => Status == "ok";
    public bool IsUpdating => Status == "updating";
    public bool IsError => Status == "error";

    public string DelegationText => Delegation switch
    {
        "valid" => "Delegated",
        "partially-valid" => "Partly delegated",
        "invalid" => "Not delegated",
        "lame" => "Lame delegation",
        "unregistered" => "Not registered",
        _ => "Delegation unknown",
    };

    public bool DelegationOk => Delegation == "valid";
    public bool DelegationBad => Delegation is "invalid" or "lame" or "unregistered";
    public bool DelegationWarn => !DelegationOk && !DelegationBad;
    /// <summary>The registrar should be told the assigned name servers.</summary>
    public bool NeedsDelegation => IsPrimary && !DelegationOk && Assigned.Count > 0;
    public string AssignedText => string.Join("\n", Assigned);
    public string RecordCountText => RecordCount == 1 ? "1 record" : $"{RecordCount.ToString(CultureInfo.InvariantCulture)} records";
    public string TtlText => $"TTL {HzRrset.TtlLabel(Ttl)}";

    public override string ToString() => Name;

    public static HzZone? From(JsonNode? n)
    {
        if (n is not JsonObject o || CfJson.Long(o["id"]) is not long id || !HetznerApi.IsId(id)) return null;
        string name = HetznerApi.Clip(CfJson.Str(o["name"]), 255).ToLowerInvariant();
        if (HetznerApi.NormalizeZoneName(name, out _) is not { } zoneName) return null;
        var ns = o["authoritative_nameservers"];
        return new HzZone
        {
            Id = id,
            Name = zoneName,
            Mode = CfJson.Str(o["mode"]) == "secondary" ? "secondary" : "primary",
            Ttl = CfJson.Int(o["ttl"]) ?? 3600,
            Status = HetznerApi.Clip(CfJson.Str(o["status"]), 20),
            RecordCount = Math.Max(0, CfJson.Int(o["record_count"]) ?? 0),
            Delegation = HetznerApi.Clip(CfJson.Str(ns?["delegation_status"]), 30),
            Assigned = CfJson.StrList(ns?["assigned"]).Take(10).Select(s => HetznerApi.Clip(s, 253)).ToList(),
            Delegated = CfJson.StrList(ns?["delegated"]).Take(10).Select(s => HetznerApi.Clip(s, 253)).ToList(),
            ProtectDelete = CfJson.Bool(o["protection"]?["delete"]),
        };
    }
}

/// <summary>One value of a record set and its comment, exactly as Hetzner has them (a save writes them back).</summary>
public sealed record HzRecordValue(string Value, string Comment);

/// <summary>A record set (name + type) with its values.</summary>
public partial class HzRrset : ObservableObject
{
    public string Name { get; init; } = "@";
    public string Type { get; init; } = "A";
    /// <summary>Null: the zone's default TTL.</summary>
    public int? Ttl { get; init; }
    public IReadOnlyList<HzRecordValue> Values { get; init; } = Array.Empty<HzRecordValue>();
    public bool Protected { get; init; }
    public string FullName { get; init; } = string.Empty;
    public int ZoneTtl { get; init; }

    /// <summary>The set has something the editor can't show and write back as it was: a value with a line break (the
    /// editor has one value per line), a record that isn't one, or more values than the editor takes.</summary>
    public bool Unreadable { get; init; }

    /// <summary>The most values the editor takes for one set.</summary>
    public const int MaxValues = 200;

    public string Id => Name + "/" + Type;
    public string DisplayName => Name == "@" ? "@ (" + FullName + ")" : Name;
    // for the screen only (clipped); the editor and a save use the values as they are
    public string ValuesText => Values.Count switch
    {
        0 => "(no values)",
        1 => HetznerApi.Clip(Values[0].Value, 200),
        _ => HetznerApi.Clip(Values[0].Value, 200) + $"  +{(Values.Count - 1).ToString(CultureInfo.InvariantCulture)} more",
    };
    public string AllValuesTip => HetznerApi.Clip(string.Join(" · ", Values.Take(20).Select(v => v.Value)), 1000);
    public string AllValuesText => string.Join("\n", Values.Select(v => v.Value));
    public string TtlText => Ttl is int t ? TtlLabel(t) : "zone";
    /// <summary>An A / AAAA set that may change (a protected one would only fail).</summary>
    public bool CanDdns => Type is "A" or "AAAA" && !Protected;
    public bool IsEditable => !Protected && Type != "SOA" && !Unreadable;

    /// <summary>The set still holds what <paramref name="other"/> holds: the same values with the same comments (in any
    /// order), the same TTL and protection. A save compares the set the editor was opened on with Hetzner's set, read
    /// right before it writes.</summary>
    public bool SameAs(HzRrset other)
        => Name == other.Name && Type == other.Type && Ttl == other.Ttl && Protected == other.Protected
           && Values.Count == other.Values.Count
           && Values.OrderBy(v => v.Value, StringComparer.Ordinal).ThenBy(v => v.Comment, StringComparer.Ordinal)
                    .SequenceEqual(other.Values.OrderBy(v => v.Value, StringComparer.Ordinal).ThenBy(v => v.Comment, StringComparer.Ordinal));

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DdnsTip))]
    private bool _ddnsOn;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DdnsTip))]
    private bool _ddnsError;
    [ObservableProperty] private bool _pendingDelete;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    private bool _isBusy;
    public bool IsIdle => !IsBusy;

    public string DdnsTip => !DdnsOn
        ? "Keep updated with my IP (dynamic DNS)"
        : DdnsError
            ? "Kept updated with your public IP, but the last check failed (Dynamic DNS… says why). Click to stop."
            : "Kept updated with your public IP. Click to stop.";

    public static string TtlLabel(int seconds) => seconds switch
    {
        >= 86400 when seconds % 86400 == 0 => $"{seconds / 86400} d",
        >= 3600 when seconds % 3600 == 0 => $"{seconds / 3600} h",
        >= 60 when seconds % 60 == 0 => $"{seconds / 60} min",
        _ => $"{seconds} s",
    };

    public static HzRrset? From(JsonNode? n, string zoneName, int zoneTtl)
    {
        if (n is not JsonObject o) return null;
        string name = CfJson.Str(o["name"]), type = CfJson.Str(o["type"]);
        if (!HetznerApi.IsRrName(name) || !HetznerApi.IsRrType(type)) return null;
        var values = new List<HzRecordValue>();
        bool unreadable = false;
        if (o["records"] is JsonArray ra)
            foreach (var r in ra)
            {
                if (r is not JsonObject ro) { unreadable = true; continue; }
                var v = new HzRecordValue(CfJson.Str(ro["value"]), CfJson.Str(ro["comment"]));
                unreadable |= v.Value.Contains('\n') || v.Value.Contains('\r');
                values.Add(v);
            }
        unreadable |= values.Count > MaxValues;
        int? ttl = CfJson.Int(o["ttl"]);
        return new HzRrset
        {
            Name = name,
            Type = type,
            Ttl = ttl is > 0 ? ttl : null,
            Values = values,
            Protected = CfJson.Bool(o["protection"]?["change"]),
            FullName = HetznerApi.FullName(name, zoneName),
            ZoneTtl = zoneTtl,
            Unreadable = unreadable,
        };
    }
}
