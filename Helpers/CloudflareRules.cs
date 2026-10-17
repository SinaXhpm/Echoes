using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace Echoes.Helpers;

/// <summary>
/// WAF custom rules and single redirects (Rulesets API) plus IP access rules: reading the API's rule objects, building
/// the request bodies, and checking what the user typed.
///
/// <para>Rulesets: GET /zones/{id}/rulesets/phases/{phase}/entrypoint lists a phase's rules (404 = none yet). A new rule
/// goes to POST /zones/{id}/rulesets/{ruleset}/rules, or, when the phase has no entry point yet, PUT …/entrypoint
/// {"rules":[rule]} (which creates it). PATCH …/rules/{rule} replaces the rule definition, so an edit starts from the
/// rule as the API returned it (fields this app doesn't show, such as logging or a custom block response, are kept) and
/// drops only the read-only ones.</para>
/// </summary>
public static class CloudflareRules
{
    public const int MaxExpressionLength = 4096;
    public const int MaxDescriptionLength = 500;

    /// <summary>Custom rule actions offered (Log is Enterprise-only and not offered; a rule using it keeps it).</summary>
    public static readonly (string Value, string Label)[] FirewallActions =
    {
        ("block", "Block"),
        ("managed_challenge", "Managed challenge"),
        ("js_challenge", "JS challenge"),
        ("challenge", "Interactive challenge"),
        ("skip", "Skip remaining custom rules"),
    };

    public static string ActionLabel(string action) => action switch
    {
        "block" => "Block",
        "managed_challenge" => "Managed challenge",
        "js_challenge" => "JS challenge",
        "challenge" => "Interactive challenge",
        "skip" => "Skip",
        "log" => "Log",
        "redirect" => "Redirect",
        "" => "No action",
        _ => action,
    };

    public static readonly int[] RedirectCodes = { 301, 302, 307, 308 };

    /// <summary>Custom rules / single redirects allowed per plan (Cloudflare's published quotas).</summary>
    public static int FirewallQuota(string plan) => plan switch { "pro" => 20, "business" => 100, "enterprise" => 1000, _ => 5 };
    public static int RedirectQuota(string plan) => plan switch { "pro" => 25, "business" => 50, "enterprise" => 300, _ => 10 };

    /// <summary>A rule as the entry point ruleset lists it, plus its full JSON (kept for edits).</summary>
    public sealed class Rule
    {
        public string Id { get; init; } = string.Empty;
        public string Description { get; init; } = string.Empty;
        public string Expression { get; init; } = string.Empty;
        public string Action { get; init; } = string.Empty;
        public bool Enabled { get; init; }
        public JsonObject Raw { get; init; } = new();
        // single redirects
        public string Target { get; init; } = string.Empty;
        public bool TargetIsExpression { get; init; }
        public int StatusCode { get; init; }
        public bool PreserveQuery { get; init; }
    }

    /// <summary>The ruleset id and its rules ("result" of the entry point), skipping malformed entries.</summary>
    public static (string RulesetId, List<Rule> Rules) ParseRuleset(JsonNode? result)
    {
        var rules = new List<Rule>();
        string id = CfJson.Str(result?["id"]);
        if (result?["rules"] is JsonArray arr)
            foreach (var n in arr)
                if (ParseRule(n) is { } r) rules.Add(r);
        return (CloudflareApi.IsId(id) ? id.ToLowerInvariant() : string.Empty, rules);
    }

    public static Rule? ParseRule(JsonNode? n)
    {
        if (n is not JsonObject o) return null;
        string id = CfJson.Str(o["id"]);
        if (!CloudflareApi.IsId(id)) return null;
        var from = o["action_parameters"]?["from_value"];
        var target = from?["target_url"];
        string? staticTarget = CfJson.StrOrNull(target?["value"]);
        string? dynamicTarget = CfJson.StrOrNull(target?["expression"]);
        return new Rule
        {
            Id = id.ToLowerInvariant(),
            Description = CfJson.Str(o["description"]),
            Expression = CfJson.Str(o["expression"]),
            Action = CfJson.Str(o["action"]),
            // "enabled" defaults to true when the API leaves it out
            Enabled = CfJson.BoolOrNull(o["enabled"]) ?? true,
            Raw = (JsonObject)o.DeepClone(),
            Target = staticTarget ?? dynamicTarget ?? string.Empty,
            TargetIsExpression = staticTarget is null && dynamicTarget is not null,
            StatusCode = CfJson.Int(from?["status_code"]) ?? 0,
            PreserveQuery = CfJson.Bool(from?["preserve_query_string"]),
        };
    }

    private static readonly string[] ReadOnlyRuleFields = { "id", "version", "last_updated", "categories" };

    /// <summary>The rule's JSON without its read-only fields: the base of an edit (PATCH replaces the definition).</summary>
    public static JsonObject Editable(JsonObject raw)
    {
        var o = (JsonObject)raw.DeepClone();
        foreach (var f in ReadOnlyRuleFields) o.Remove(f);
        return o;
    }

    /// <summary>Enable / disable: the whole definition with only "enabled" changed.</summary>
    public static JsonObject WithEnabled(JsonObject raw, bool enabled)
    {
        var o = Editable(raw);
        o["enabled"] = enabled;
        return o;
    }

    /// <summary>A custom rule body. An unchanged action keeps its action_parameters (a custom block page, a skip's
    /// phases…); a new one gets what it needs (skip → the rest of this ruleset).</summary>
    public static JsonObject FirewallBody(JsonObject? original, string description, string expression, string action, bool enabled)
    {
        var o = original is null ? new JsonObject() : Editable(original);
        string before = CfJson.Str(o["action"]);
        o["description"] = description;
        o["expression"] = expression;
        o["action"] = action;
        o["enabled"] = enabled;
        if (action != before || original is null)
        {
            if (action == "skip") o["action_parameters"] = new JsonObject { ["ruleset"] = "current" };
            else o.Remove("action_parameters");
        }
        return o;
    }

    /// <summary>A single redirect body: action "redirect" with from_value {target_url {value | expression}, status_code,
    /// preserve_query_string}; other keys of an existing from_value are kept.</summary>
    public static JsonObject RedirectBody(JsonObject? original, string description, string expression, string target,
                                          int statusCode, bool preserveQuery, bool enabled)
    {
        var o = original is null ? new JsonObject() : Editable(original);
        o["description"] = description;
        o["expression"] = expression;
        o["action"] = "redirect";
        o["enabled"] = enabled;
        var parameters = o["action_parameters"] as JsonObject ?? new JsonObject();
        var from = parameters["from_value"] as JsonObject ?? new JsonObject();
        from["target_url"] = IsStaticUrl(target)
            ? new JsonObject { ["value"] = target }
            : new JsonObject { ["expression"] = target };
        from["status_code"] = statusCode;
        from["preserve_query_string"] = preserveQuery;
        parameters["from_value"] = from;
        o["action_parameters"] = parameters;
        return o;
    }

    /// <summary>A plain absolute URL (goes as target_url.value); anything else (concat(…), wildcard_replace(…), a field)
    /// is an expression (target_url.expression).</summary>
    public static bool IsStaticUrl(string target)
    {
        string t = target.Trim();
        if (t.Length == 0 || t.IndexOfAny(new[] { ' ', '"', '(', ')', '\t', '\n', '\r' }) >= 0) return false;
        return Uri.TryCreate(t, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)
               && !string.IsNullOrEmpty(u.Host);
    }

    /// <summary>Why the text can't be a rule expression (null when it can).</summary>
    public static string? CheckExpression(string expression)
    {
        string e = expression.Trim();
        if (e.Length == 0) return "Enter the expression the rule matches, or pick an example.";
        if (e.Length > MaxExpressionLength) return $"The expression can be at most {MaxExpressionLength} characters.";
        foreach (char c in e)
            if (char.IsControl(c) && c is not ('\n' or '\r' or '\t')) return "The expression contains a control character.";
        return null;
    }

    public static string? CheckDescription(string description)
    {
        if (description.Length > MaxDescriptionLength) return $"The name can be at most {MaxDescriptionLength} characters.";
        foreach (char c in description)
            if (char.IsControl(c)) return "The name can't contain line breaks.";
        return null;
    }

    /// <summary>Why a redirect target is unusable (null when fine).</summary>
    public static string? CheckTarget(string target)
    {
        string t = target.Trim();
        if (t.Length == 0) return "Enter where to redirect to: a URL like https://example.com/new, or an expression.";
        if (t.Length > MaxExpressionLength) return "The target is too long.";
        foreach (char c in t)
            if (char.IsControl(c)) return "The target contains a line break or control character.";
        if (!IsStaticUrl(t) && t.StartsWith("http", StringComparison.OrdinalIgnoreCase) && !t.Contains('('))
            return "That URL isn't valid. Use a full URL like https://example.com/page, or an expression like concat(…).";
        return null;
    }

    public sealed class Example
    {
        public Example(string label, string description, string expression, string action = "", string target = "",
                       int status = 301, bool preserveQuery = false)
        {
            Label = label;
            Description = description;
            Expression = expression;
            Action = action;
            Target = target;
            Status = status;
            PreserveQuery = preserveQuery;
        }

        public string Label { get; }
        public string Description { get; }
        public string Expression { get; }
        public string Action { get; }
        public string Target { get; }
        public int Status { get; }
        public bool PreserveQuery { get; }
        public override string ToString() => Label;
    }

    /// <summary>Starting points for a custom rule ("{zone}" is replaced with the zone name).</summary>
    public static IReadOnlyList<Example> FirewallExamples(string zone) => new[]
    {
        new Example("Block a country (replace XX)", "Block country XX", "(ip.src.country eq \"XX\")", "block"),
        new Example("Challenge everyone outside one country", "Challenge visitors outside DE", "(ip.src.country ne \"DE\")", "managed_challenge"),
        new Example("Protect the admin area", "Protect /wp-admin", "(http.request.uri.path contains \"/wp-admin\" and not ip.src in {203.0.113.10})", "managed_challenge"),
        new Example("Protect the login page", "Challenge login attempts", "(http.request.uri.path eq \"/wp-login.php\")", "managed_challenge"),
        new Example("Block an IP address or range", "Block 198.51.100.0/24", "(ip.src in {198.51.100.0/24})", "block"),
        new Example("Block an AS number", "Block AS64496", "(ip.src.asnum eq 64496)", "block"),
        new Example("Challenge known bad user agents", "Challenge scripted clients", "(http.user_agent contains \"curl\" or http.user_agent contains \"python-requests\")", "managed_challenge"),
        new Example("Block xmlrpc.php", "Block xmlrpc.php", "(http.request.uri.path eq \"/xmlrpc.php\")", "block"),
        new Example("Allow my IP past the other rules", "Allow my office IP", "(ip.src eq 203.0.113.10)", "skip"),
        new Example("Challenge traffic to one host", "Challenge " + "staging." + zone, $"(http.host eq \"staging.{zone}\")", "managed_challenge"),
    };

    /// <summary>Starting points for a single redirect.</summary>
    public static IReadOnlyList<Example> RedirectExamples(string zone) => new[]
    {
        new Example("Redirect www to the root domain", "www to root", $"(http.host eq \"www.{zone}\")",
            target: $"concat(\"https://{zone}\", http.request.uri.path)", status: 301, preserveQuery: true),
        new Example("Redirect the root domain to www", "Root to www", $"(http.host eq \"{zone}\")",
            target: $"concat(\"https://www.{zone}\", http.request.uri.path)", status: 301, preserveQuery: true),
        new Example("Redirect one page", "Old page to new page", "(http.request.uri.path eq \"/old-page\")",
            target: $"https://{zone}/new-page", status: 301, preserveQuery: true),
        new Example("Redirect a folder", "Old blog folder", "(starts_with(http.request.uri.path, \"/blog/\"))",
            target: $"concat(\"https://{zone}/news/\", substring(http.request.uri.path, 6))", status: 301, preserveQuery: true),
        new Example("Send a country to a localized site", "Germany to /de", "(ip.src.country eq \"DE\" and not starts_with(http.request.uri.path, \"/de/\"))",
            target: $"concat(\"https://{zone}/de\", http.request.uri.path)", status: 302, preserveQuery: true),
        new Example("Move the whole site to a new domain", "Site moved", "(http.host eq \"" + zone + "\" or ends_with(http.host, \"." + zone + "\"))",
            target: "concat(\"https://new-domain.example\", http.request.uri.path)", status: 301, preserveQuery: true),
    };

    // ================================================================ IP access rules

    public static readonly (string Value, string Label)[] AccessModes =
    {
        ("block", "Block"),
        ("managed_challenge", "Managed challenge"),
        ("js_challenge", "JS challenge"),
        ("challenge", "Interactive challenge"),
        ("whitelist", "Allow"),
    };

    public static string AccessModeLabel(string mode) => mode switch
    {
        "block" => "Block",
        "managed_challenge" => "Managed challenge",
        "js_challenge" => "JS challenge",
        "challenge" => "Interactive challenge",
        "whitelist" => "Allow",
        _ => mode,
    };

    public static string AccessTargetLabel(string target) => target switch
    {
        "ip" => "IPv4 address",
        "ip6" => "IPv6 address",
        "ip_range" => "IP range",
        "asn" => "AS number",
        "country" => "Country",
        _ => target,
    };

    /// <summary>
    /// What an IP access value is, found from the text itself (no type picker): an IPv4 / IPv6 address, a range (IPv4
    /// /16 or /24, IPv6 /32, /48 or /64 — what Cloudflare accepts), an AS number ("AS13335" or "13335"), or a country
    /// (code or English name). Returns the target and the value in the form the API wants, or an error.
    /// </summary>
    public static bool TryAccessTarget(string text, out string target, out string value, out string error)
    {
        target = value = error = string.Empty;
        string t = (text ?? string.Empty).Trim();
        if (t.Length == 0) { error = "Enter an IP address, a range like 198.51.100.0/24, an AS number like AS13335, or a country."; return false; }
        if (t.Length > 100) { error = "That value is too long."; return false; }

        int slash = t.IndexOf('/');
        if (slash > 0)
        {
            string ipPart = t[..slash], bits = t[(slash + 1)..];
            if (!IPAddress.TryParse(ipPart, out var ip) || !int.TryParse(bits, NumberStyles.None, CultureInfo.InvariantCulture, out int prefix)
                || (ip.AddressFamily == AddressFamily.InterNetwork && !CloudflareBackup.IsIPv4(ipPart)))
            { error = "That isn't an IP range. Write it like 198.51.100.0/24 or 2001:db8::/48."; return false; }
            bool v4 = ip.AddressFamily == AddressFamily.InterNetwork;
            if (v4 ? prefix is not (16 or 24) : prefix is not (32 or 48 or 64))
            {
                error = v4 ? "Cloudflare takes IPv4 ranges of /16 or /24 only. For other sizes, use a WAF custom rule (ip.src in {…})."
                           : "Cloudflare takes IPv6 ranges of /32, /48 or /64 only. For other sizes, use a WAF custom rule (ip.src in {…}).";
                return false;
            }
            var network = Network(ip, prefix);
            target = "ip_range";
            value = network + "/" + prefix.ToString(CultureInfo.InvariantCulture);
            return true;
        }

        if (CloudflareBackup.IsIPv4(t) && IPAddress.TryParse(t, out var v4addr))
        {
            target = "ip";
            value = v4addr.ToString();
            return true;
        }
        if (CloudflareBackup.IsIPv6(t) && IPAddress.TryParse(t, out var v6addr))
        {
            target = "ip6";
            value = v6addr.ToString();
            return true;
        }

        string asn = t.StartsWith("AS", StringComparison.OrdinalIgnoreCase) ? t[2..].Trim() : t;
        if (asn.Length is > 0 and <= 10 && long.TryParse(asn, NumberStyles.None, CultureInfo.InvariantCulture, out long n) && n is > 0 and <= 4294967295)
        {
            target = "asn";
            value = "AS" + n.ToString(CultureInfo.InvariantCulture);
            return true;
        }

        if (CloudflareCountries.Find(t) is { } cc)
        {
            target = "country";
            value = cc;
            return true;
        }

        error = "Not an IP address, range, AS number or country. Examples: 198.51.100.7 · 198.51.100.0/24 · AS13335 · DE or Germany.";
        return false;
    }

    // The range's network address (host bits cleared), as Cloudflare lists it.
    private static string Network(IPAddress ip, int prefix)
    {
        byte[] b = ip.GetAddressBytes();
        for (int i = 0; i < b.Length; i++)
        {
            int keep = Math.Clamp(prefix - i * 8, 0, 8);
            b[i] &= (byte)(0xFF << (8 - keep));
        }
        return new IPAddress(b).ToString();
    }

    public static string? CheckNote(string note)
    {
        if (note.Length > 500) return "The note can be at most 500 characters.";
        foreach (char c in note)
            if (char.IsControl(c)) return "The note can't contain line breaks.";
        return null;
    }
}
