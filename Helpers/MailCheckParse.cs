using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace Echoes.Helpers;

/// <summary>One SPF term: a mechanism ("include", "ip4", "all" …, with its qualifier) or a modifier ("redirect", "exp").</summary>
public sealed record SpfTerm(char Qualifier, string Name, string? Value, bool IsModifier, string Raw);

/// <summary>A parsed SPF record (RFC 7208). <see cref="Errors"/>: terms that make it a permerror.</summary>
public sealed class SpfRecord
{
    public List<SpfTerm> Terms { get; } = new();
    public List<string> Errors { get; } = new();
    public SpfTerm? All => Terms.LastOrDefault(t => !t.IsModifier && t.Name == "all");
    public string? Redirect => Terms.FirstOrDefault(t => t.IsModifier && t.Name == "redirect")?.Value;

    public static bool IsSpf(string txt)
    {
        string t = txt.TrimStart();
        return t.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase) && (t.Length == 6 || t[6] == ' ');
    }

    private static readonly HashSet<string> Mechanisms = new(StringComparer.Ordinal) { "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists" };

    public static SpfRecord Parse(string record)
    {
        var rec = new SpfRecord();
        var tokens = record.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (string token in tokens.Skip(1))   // tokens[0] is v=spf1
        {
            if (rec.Terms.Count >= 200) { rec.Errors.Add("the record has too many terms"); break; }
            int eq = token.IndexOf('='), colon = token.IndexOf(':'), slash = token.IndexOf('/');
            bool modifier = eq > 0 && (colon < 0 || eq < colon) && (slash < 0 || eq < slash);
            if (modifier)
            {
                string name = token[..eq].ToLowerInvariant();
                string modValue = token[(eq + 1)..];
                if (!IsModifierName(name)) { rec.Errors.Add($"'{Clip(token)}' isn't a valid modifier"); continue; }
                if (name is "redirect" or "exp" && rec.Terms.Any(t => t.IsModifier && t.Name == name))
                    rec.Errors.Add($"{name}= appears more than once");
                rec.Terms.Add(new SpfTerm('+', name, modValue, true, token));
                continue;
            }
            char q = '+';
            string body = token;
            if (body.Length > 0 && body[0] is '+' or '-' or '~' or '?') { q = body[0]; body = body[1..]; }
            int cut = body.IndexOfAny(new[] { ':', '/' });
            string mech = (cut < 0 ? body : body[..cut]).ToLowerInvariant();
            string? arg = cut < 0 ? null : body[cut..];
            if (!Mechanisms.Contains(mech)) { rec.Errors.Add($"unknown term '{Clip(token)}'"); continue; }
            string? value = arg is { Length: > 0 } && arg[0] == ':' ? arg[1..] : arg;
            switch (mech)
            {
                case "all" when arg != null:
                    rec.Errors.Add("'all' takes no argument"); continue;
                case "include" or "exists" when string.IsNullOrEmpty(value) || arg![0] != ':':
                    rec.Errors.Add($"{mech} needs a domain ({mech}:example.com)"); continue;
                case "ip4" or "ip6" when !ValidIp(mech, value):
                    rec.Errors.Add($"'{Clip(token)}' isn't a valid {mech} address / range"); continue;
            }
            rec.Terms.Add(new SpfTerm(q, mech, value, false, token));
        }
        return rec;
    }

    private static bool IsModifierName(string n)
        => n.Length > 0 && char.IsAsciiLetter(n[0]) && n.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    private static bool ValidIp(string mech, string? value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        string addr = value;
        int max = mech == "ip4" ? 32 : 128;
        int slash = value.IndexOf('/');
        if (slash >= 0)
        {
            addr = value[..slash];
            if (!int.TryParse(value[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int len) || len > max) return false;
        }
        if (!IPAddress.TryParse(addr, out var ip)) return false;
        return mech == "ip4" ? ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && addr.Count(c => c == '.') == 3
                             : ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
    }

    /// <summary>True when the domain argument uses SPF macros (%{i} …) — it can't be followed without a real message.</summary>
    public static bool HasMacro(string? domain) => domain != null && domain.Contains('%');

    private static string Clip(string s) => s.Length > 40 ? s[..40] + "…" : s;
}

/// <summary>"k=v; k=v" tag lists (DMARC, DKIM, MTA-STS TXT, TLS-RPT). Keys lower-case; the first of a repeated key wins.</summary>
public static class TagList
{
    public static Dictionary<string, string> Parse(string text, out List<string> order)
    {
        var tags = new Dictionary<string, string>(StringComparer.Ordinal);
        order = new List<string>();
        foreach (string part in text.Split(';'))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0) continue;
            string k = part[..eq].Trim().ToLowerInvariant();
            string v = part[(eq + 1)..].Trim();
            if (k.Length == 0 || tags.ContainsKey(k)) continue;
            tags[k] = v;
            order.Add(k);
            if (tags.Count >= 64) break;
        }
        return tags;
    }

    public static Dictionary<string, string> Parse(string text) => Parse(text, out _);
}

/// <summary>A DMARC record (RFC 7489) read for the checks the email check makes.</summary>
public sealed class DmarcRecord
{
    public string? Policy { get; init; }
    public string? SubdomainPolicy { get; init; }
    public int Pct { get; init; } = 100;
    public bool PctValid { get; init; } = true;
    public List<string> Rua { get; init; } = new();
    public List<string> Ruf { get; init; } = new();
    public bool VersionFirst { get; init; }
    public Dictionary<string, string> Tags { get; init; } = new();

    public static bool IsDmarc(string txt) => txt.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase);

    public static DmarcRecord Parse(string text)
    {
        var tags = TagList.Parse(text, out var order);
        int pct = 100;
        bool pctOk = true;
        if (tags.TryGetValue("pct", out string? p))
            pctOk = int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out pct) && pct is >= 0 and <= 100;
        static string? Pol(string? v) => v?.ToLowerInvariant() is "none" or "quarantine" or "reject" ? v.ToLowerInvariant() : null;
        static List<string> Uris(string? v) => v == null ? new() : v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Take(10).ToList();
        return new DmarcRecord
        {
            Tags = tags,
            VersionFirst = order.Count > 0 && order[0] == "v" && tags["v"].Equals("DMARC1", StringComparison.OrdinalIgnoreCase),
            Policy = Pol(tags.GetValueOrDefault("p")),
            SubdomainPolicy = Pol(tags.GetValueOrDefault("sp")),
            Pct = pctOk ? pct : 100,
            PctValid = pctOk,
            Rua = Uris(tags.GetValueOrDefault("rua")),
            Ruf = Uris(tags.GetValueOrDefault("ruf")),
        };
    }
}

/// <summary>A DKIM key record (RFC 6376 §3.6.1): key type and size when the key is readable.</summary>
public sealed class DkimKey
{
    public string KeyType { get; init; } = "rsa";
    public bool Revoked { get; init; }
    public bool Testing { get; init; }
    /// <summary>RSA modulus bits (0 when unknown / not RSA).</summary>
    public int Bits { get; init; }
    public bool Readable { get; init; }

    /// <summary>"RSA 2048", "Ed25519", "RSA (unreadable key)", "revoked".</summary>
    public string Describe()
    {
        if (Revoked) return "revoked (empty key)";
        if (KeyType == "ed25519") return Readable ? "Ed25519" : "Ed25519 (unreadable key)";
        if (KeyType == "rsa") return Bits > 0 ? $"RSA {Bits}" : "RSA (unreadable key)";
        return KeyType.Length > 20 ? KeyType[..20] + "…" : KeyType;   // the record's own k= value: any length
    }

    /// <summary>Looks like a DKIM key record at all (a wildcard TXT such as an SPF record doesn't).</summary>
    public static bool IsDkim(string txt)
    {
        var t = TagList.Parse(txt);
        return t.ContainsKey("p") && (!t.TryGetValue("v", out var v) || v.Equals("DKIM1", StringComparison.OrdinalIgnoreCase));
    }

    public static DkimKey Parse(string txt)
    {
        var t = TagList.Parse(txt);
        string k = (t.GetValueOrDefault("k") ?? "rsa").ToLowerInvariant();
        string p = new string((t.GetValueOrDefault("p") ?? "").Where(c => !char.IsWhiteSpace(c)).ToArray());
        bool testing = (t.GetValueOrDefault("t") ?? "").Split(':').Any(f => f.Trim().Equals("y", StringComparison.OrdinalIgnoreCase));
        if (p.Length == 0) return new DkimKey { KeyType = k, Revoked = true, Testing = testing };
        if (p.Length > 8192) return new DkimKey { KeyType = k, Testing = testing };
        byte[] der;
        try { der = Convert.FromBase64String(p); }
        catch (FormatException) { return new DkimKey { KeyType = k, Testing = testing }; }
        if (k == "ed25519") return new DkimKey { KeyType = k, Testing = testing, Readable = der.Length == 32 };
        if (k != "rsa") return new DkimKey { KeyType = k, Testing = testing };
        int bits = 0;
        try
        {
            using var rsa = RSA.Create();
            try { rsa.ImportSubjectPublicKeyInfo(der, out _); }
            catch (CryptographicException) { rsa.ImportRSAPublicKey(der, out _); }   // some publish the bare PKCS#1 key
            bits = rsa.KeySize;
        }
        catch { /* not a key this platform reads */ }
        return new DkimKey { KeyType = k, Testing = testing, Bits = bits, Readable = bits > 0 };
    }
}

/// <summary>An MTA-STS policy file (RFC 8461 §3.2).</summary>
public sealed class MtaStsPolicy
{
    public string? Version { get; init; }
    public string? Mode { get; init; }
    public long MaxAge { get; init; } = -1;
    public List<string> Mx { get; init; } = new();

    public static MtaStsPolicy Parse(string text)
    {
        string? version = null, mode = null;
        long maxAge = -1;
        var mx = new List<string>();
        foreach (string raw in text.Split('\n').Take(200))
        {
            string line = raw.TrimEnd('\r');
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            string k = line[..colon].Trim().ToLowerInvariant(), v = line[(colon + 1)..].Trim();
            switch (k)
            {
                case "version": version ??= v; break;
                case "mode": mode ??= v.ToLowerInvariant(); break;
                case "max_age": if (maxAge < 0 && long.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out long a)) maxAge = a; break;
                case "mx": if (mx.Count < 50 && v.Length > 0) mx.Add(v.ToLowerInvariant().TrimEnd('.')); break;
            }
        }
        return new MtaStsPolicy { Version = version, Mode = mode, MaxAge = maxAge, Mx = mx };
    }

    /// <summary>RFC 8461 §4.1: "mail.example.com" matches exactly; "*.example.com" matches one extra leftmost label.</summary>
    public bool Covers(string host)
    {
        string h = host.ToLowerInvariant().TrimEnd('.');
        foreach (string p in Mx)
        {
            if (p.StartsWith("*.", StringComparison.Ordinal))
            {
                int dot = h.IndexOf('.');
                if (dot > 0 && h[(dot + 1)..] == p[2..]) return true;
            }
            else if (h == p) return true;
        }
        return false;
    }
}
