using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _hashIdInput = string.Empty;
    [ObservableProperty] private string _hashIdOutput = string.Empty;

    private static readonly Regex HexOnlyRe = new("^[0-9a-fA-F]+$", RegexOptions.None, InternalRegexTimeout);
    private static readonly Regex B64OnlyRe = new("^[A-Za-z0-9+/]+={0,2}$", RegexOptions.None, InternalRegexTimeout);
    private static readonly Regex JwtLikeRe = new(@"^eyJ[A-Za-z0-9_-]+\.", RegexOptions.None, InternalRegexTimeout);
    // Django's "<algorithm>$<iterations?>$<salt>$<hash>" (pbkdf2_sha256$…, sha1$…, md5$…, argon2$…);
    // the same "alg$salt$hash" shape is what old Werkzeug/Flask wrote for sha256$ / sha512$.
    private static readonly Regex DjangoRe = new(@"^(pbkdf2_sha256|pbkdf2_sha1|bcrypt_sha256|argon2|scrypt|sha256|sha512|sha1|md5|unsalted_md5|unsalted_sha1|crypt)\$", RegexOptions.None, InternalRegexTimeout);
    // Current Werkzeug/Flask generate_password_hash(): "pbkdf2:sha256:600000$salt$hash", "scrypt:32768:8:1$salt$hash"
    private static readonly Regex WerkzeugRe = new(@"^(pbkdf2:sha(?:1|256|512)|scrypt)(?::\d+)*\$", RegexOptions.None, InternalRegexTimeout);

    // Ordered prefix table: first match wins, so longer/more specific prefixes come first.
    private static readonly (string Prefix, string Name)[] HashPrefixes =
    {
        ("$2a$", "bcrypt"), ("$2b$", "bcrypt"), ("$2y$", "bcrypt"), ("$2x$", "bcrypt (legacy $2x$)"), ("$2$", "bcrypt (original $2$)"),
        ("$y$", "yescrypt (modern Linux /etc/shadow)"),
        ("$gy$", "gost-yescrypt"),
        ("$7$", "scrypt (crypt $7$)"),
        ("$scrypt$", "scrypt"),
        ("$argon2", "Argon2"),
        ("$pbkdf2", "PBKDF2 (passlib)"),
        ("$sha1$", "SHA-1 crypt (NetBSD $sha1$)"),
        ("$apr1$", "Apache MD5 (htpasswd $apr1$)"),
        ("$1$", "MD5 crypt (Unix)"),
        ("$5$", "SHA-256 crypt (Unix)"),
        ("$6$", "SHA-512 crypt (Unix)"),
        ("$P$", "phpass (WordPress / Drupal 7)"),
        ("$H$", "phpass (phpBB3)"),
        ("{SSHA512}", "Salted SHA-512 (LDAP {SSHA512})"),
        ("{SSHA256}", "Salted SHA-256 (LDAP {SSHA256})"),
        ("{SSHA}", "Salted SHA-1 (LDAP {SSHA})"),
        ("{SHA512}", "SHA-512 (LDAP {SHA512})"),
        ("{SHA256}", "SHA-256 (LDAP {SHA256})"),
        ("{SHA}", "SHA-1 (LDAP {SHA})"),
        ("{SMD5}", "Salted MD5 (LDAP {SMD5})"),
        ("{MD5}", "MD5 (LDAP {MD5})"),
        ("{CRYPT}", "crypt(3) (LDAP {CRYPT})"),
    };

    [RelayCommand]
    private void RunHashId()
    {
        try
        {
            ResetError();
            var h = HashIdInput.Trim();
            if (string.IsNullOrEmpty(h)) return;

            var candidates = new List<string>();
            var notes = new List<string>();
            bool isHex = HexOnlyRe.IsMatch(h);   // computed once, reused for the branch + charset label

            string? prefixed = null;
            foreach (var (prefix, name) in HashPrefixes)
                if (h.StartsWith(prefix, StringComparison.Ordinal)) { prefixed = name; break; }

            if (prefixed != null) candidates.Add(prefixed);
            else if (DjangoRe.Match(h) is { Success: true } dj)
                candidates.Add(dj.Groups[1].Value is "sha256" or "sha512"
                    ? $"Django-style salted {dj.Groups[1].Value.ToUpperInvariant()} ({dj.Groups[1].Value}$salt$hash — legacy Werkzeug / Flask)"
                    : $"Django ({dj.Groups[1].Value})");
            else if (WerkzeugRe.Match(h) is { Success: true } wz) candidates.Add($"Werkzeug / Flask ({wz.Groups[1].Value})");
            else if (JwtLikeRe.IsMatch(h)) candidates.Add("JWT (JSON Web Token)");
            else if (h.Length == 41 && h[0] == '*' && HexOnlyRe.IsMatch(h[1..])) candidates.Add("MySQL 4.1+ / 5.x PASSWORD() (*SHA1(SHA1(pw)))");
            else if (h.Length == 65 && h[32] == ':' && HexOnlyRe.IsMatch(h[..32]) && HexOnlyRe.IsMatch(h[33..]))
            {
                // pwdump / secretsdump "LM:NT" pair
                candidates.Add("LM:NTLM pair (Windows SAM dump format)");
                if (h[..32].Equals("aad3b435b51404eeaad3b435b51404ee", StringComparison.OrdinalIgnoreCase))
                    notes.Add("The LM half is the well-known empty value — LM storage is disabled for this account.");
            }
            else if (isHex)
            {
                switch (h.Length)
                {
                    case 8: candidates.AddRange(new[] { "CRC-32", "Adler-32" }); break;
                    case 16: candidates.AddRange(new[] { "CRC-64", "MySQL 3.23 (OLD_PASSWORD)", "Half MD5" }); break;
                    case 32:
                        candidates.AddRange(new[] { "MD5", "NTLM", "LM", "MD4", "MD2" });
                        notes.Add("32 hex chars is ambiguous: MD5, NTLM and LM all look identical — context decides.");
                        if (h.Equals("aad3b435b51404eeaad3b435b51404ee", StringComparison.OrdinalIgnoreCase))
                            notes.Add("This exact value is the LM hash of an empty password (LM disabled).");
                        break;
                    case 40: candidates.AddRange(new[] { "SHA-1", "RIPEMD-160", "MySQL5 (without the leading *)" }); break;
                    case 56: candidates.AddRange(new[] { "SHA-224", "SHA3-224" }); break;
                    case 64: candidates.AddRange(new[] { "SHA-256", "SHA3-256", "BLAKE2s-256" }); break;
                    case 96: candidates.AddRange(new[] { "SHA-384", "SHA3-384" }); break;
                    case 128: candidates.AddRange(new[] { "SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool" }); break;
                    default: candidates.Add($"Unknown hex digest ({h.Length} chars)"); break;
                }
            }
            else if (B64OnlyRe.IsMatch(h) && h.Length % 4 == 0)
                candidates.Add("Base64-encoded data (not a hex hash)");

            if (candidates.Count == 0) candidates.Add("Unrecognized format.");

            var sb = new StringBuilder();
            Row2(sb, "Length", h.Length.ToString());
            Row2(sb, "Charset", isHex ? "hex" : "mixed");
            sb.AppendLine();
            sb.AppendLine("Possible types:");
            foreach (var c in candidates) sb.AppendLine("  • " + c);
            if (notes.Count > 0)
            {
                sb.AppendLine();
                foreach (var n in notes) sb.AppendLine("Note: " + n);
            }

            HashIdOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }
}
