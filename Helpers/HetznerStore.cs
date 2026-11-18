using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Echoes.Helpers;

/// <summary>One saved Hetzner project: its name, API token and optional proxy. Never printed.</summary>
public sealed class HzProjectData
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public bool UseProxy { get; set; }
    public string Proxy { get; set; } = string.Empty;
    public string ProxyUser { get; set; } = string.Empty;
    public string ProxyPass { get; set; } = string.Empty;
    /// <summary>Came in with a backup restore (or from a value this install didn't seal): usable by hand, but dynamic
    /// DNS doesn't take its token until the user confirms the project is theirs.</summary>
    public bool Restored { get; set; }
    /// <summary>Hetzner refused a change as "forbidden": the token is a Read token. Cleared by a new token.</summary>
    public bool ReadOnly { get; set; }

    public HzProjectData Clone() => (HzProjectData)MemberwiseClone();

    public override string ToString() => Name;
}

/// <summary>
/// Where the Hetzner tool keeps its projects: ONE profile setting, "hetzner.projects", sealed with the per-install device
/// key (<see cref="SecretProtector"/>, "enc2:"), as the Monitor's Telegram token is. No master password: dynamic DNS
/// must run in the background without anything being unlocked. Where this install has no key file, nothing is stored
/// (the projects last for the session), since the older machine-derived seal isn't good enough for a token.
///
/// <para>A backup carries the list in the clear inside the password-encrypted backup (ProfileService does this for
/// every sealed value) and seals it again on import. Since a backup may come from someone else, the import marks every
/// project in it <see cref="HzProjectData.Restored"/> and switches its proxy off (<see cref="DisarmJson"/>): the tool
/// then asks the user to confirm a restored project before dynamic DNS uses its token. Otherwise a planted backup could
/// have this device report its public IP into someone else's DNS. A value that isn't sealed with this install's key
/// (plain text, the legacy seal) is treated the same way when loaded.</para>
/// </summary>
public static class HetznerStore
{
    public const string SettingKey = "hetzner.projects";
    public const string ActiveKey = "hetzner.active";
    public const int MaxProjects = 20;

    /// <summary>How the saved list opened.</summary>
    public enum LoadResult
    {
        /// <summary>Opened (or nothing was saved).</summary>
        Ok,
        /// <summary>No device key this run: the saved list is kept as it is and must not be written over.</summary>
        Unreadable,
        /// <summary>Sealed with another install's key (or damaged): it can never open here.</summary>
        Lost,
    }

    public static List<HzProjectData> Load(ISettings store, out LoadResult result)
    {
        result = LoadResult.Ok;
        string stored = store.GetSetting(SettingKey) ?? string.Empty;
        if (stored.Length == 0) return new List<HzProjectData>();
        string json = SecretProtector.Unprotect(stored);
        if (json.Length == 0)
        {
            result = SecretProtector.IsKeyAvailable ? LoadResult.Lost : LoadResult.Unreadable;
            return new List<HzProjectData>();
        }
        var list = FromJson(json);
        // not sealed by this install (hand-made, legacy, a value a backup brought in raw): confirm before background use
        bool foreign = !stored.StartsWith("enc2:", StringComparison.Ordinal);
        if (foreign)
            foreach (var p in list) p.Restored = true;
        return list;
    }

    /// <summary>
    /// Seal and store the list (an empty list removes the setting). False when this install can't seal with its own
    /// key: nothing was written, and the projects last for this session only.
    /// </summary>
    public static bool Save(ISettings store, IReadOnlyList<HzProjectData> projects)
    {
        if (projects.Count == 0)
        {
            store.Remove(SettingKey);
            return true;
        }
        string sealedValue = SecretProtector.Protect(ToJson(projects));
        if (!SecretProtector.IsProtected(sealedValue) || SecretProtector.IsLegacy(sealedValue)) return false;
        store.SetSetting(SettingKey, sealedValue);
        return true;
    }

    public static string NewId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

    internal static string ToJson(IReadOnlyList<HzProjectData> projects)
    {
        var arr = new JsonArray();
        foreach (var p in projects)
            arr.Add((JsonNode)new JsonObject
            {
                ["id"] = p.Id,
                ["name"] = p.Name,
                ["token"] = p.Token,
                ["useProxy"] = p.UseProxy,
                ["proxy"] = p.Proxy,
                ["proxyUser"] = p.ProxyUser,
                ["proxyPass"] = p.ProxyPass,
                ["restored"] = p.Restored,
                ["readOnly"] = p.ReadOnly,
            });
        return new JsonObject { ["v"] = 1, ["projects"] = arr }.ToJsonString();
    }

    /// <summary>The projects in a list's JSON; anything unreadable or without a usable token is left out.</summary>
    internal static List<HzProjectData> FromJson(string json)
    {
        var list = new List<HzProjectData>();
        JsonArray? arr;
        try { arr = (JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { MaxDepth = 16 }) as JsonObject)?["projects"] as JsonArray; }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException) { return list; }
        if (arr is null) return list;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var n in arr)
        {
            if (n is not JsonObject o) continue;
            try
            {
                string token = CfJson.Str(o["token"]).Trim();
                if (!HetznerApi.IsTokenShape(token)) continue;
                string id = CfJson.Str(o["id"]);
                if (id.Length is 0 or > 32 || !ids.Add(id)) id = NewId();
                ids.Add(id);
                list.Add(new HzProjectData
                {
                    Id = id,
                    Name = Clip(CfJson.Str(o["name"]), 60),
                    Token = token,
                    UseProxy = CfJson.Bool(o["useProxy"]),
                    Proxy = Clip(CfJson.Str(o["proxy"]), 300),
                    ProxyUser = Clip(CfJson.Str(o["proxyUser"]), 200),
                    ProxyPass = CfJson.Str(o["proxyPass"]),
                    Restored = CfJson.Bool(o["restored"]),
                    ReadOnly = CfJson.Bool(o["readOnly"]),
                });
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { /* a broken entry: left out */ }
            if (list.Count >= MaxProjects) break;
        }
        return list;
    }

    /// <summary>
    /// A backup's project list on its way in: every project becomes <see cref="HzProjectData.Restored"/> and its proxy is
    /// switched off. Returns the rewritten JSON (null when it isn't a project list), and adds what was turned off to
    /// <paramref name="disabled"/> ("hetzner.projects" for the confirmation, "hetzner.projects/proxy" for proxies).
    /// </summary>
    internal static string? DisarmJson(string json, List<string> disabled)
    {
        var list = FromJson(json);
        if (list.Count == 0) return null;
        bool proxy = false;
        foreach (var p in list)
        {
            proxy |= p.UseProxy;
            p.UseProxy = false;
            p.Restored = true;
        }
        if (!disabled.Contains(SettingKey)) disabled.Add(SettingKey);
        if (proxy && !disabled.Contains(SettingKey + "/proxy")) disabled.Add(SettingKey + "/proxy");
        return ToJson(list);
    }

    private static string Clip(string? s, int max)
    {
        s = (s ?? string.Empty).Trim();
        return s.Length > max ? s[..max] : s;
    }
}
