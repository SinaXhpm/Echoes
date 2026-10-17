using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _jwtInput = string.Empty;
    [ObservableProperty] private string _jwtKey = string.Empty;     // optional: HMAC secret or PEM public key
    [ObservableProperty] private string _jwtOutput = string.Empty;
    [ObservableProperty] private string _jwtVerify = string.Empty;  // signature-verification status line

    [RelayCommand]
    private void RunJwt()
    {
        try
        {
            ResetError();
            JwtVerify = string.Empty;
            var token = JwtInput.Trim();
            if (token.Length == 0) return;

            var parts = token.Split('.');
            if (parts.Length is < 2 or > 3)
            {
                ErrorMessage = "Not a JWT — expected header.payload.signature.";
                return;
            }

            string headerJson = DecodeUtf8(parts[0]);
            string payloadJson = DecodeUtf8(parts[1]);

            var sb = new StringBuilder();
            sb.AppendLine("── HEADER ──");
            sb.AppendLine(Pretty(headerJson));
            sb.AppendLine();
            sb.AppendLine("── PAYLOAD ──");
            sb.AppendLine(Pretty(payloadJson));

            string claims = DescribeClaims(payloadJson);
            if (claims.Length > 0)
            {
                sb.AppendLine();
                sb.AppendLine("── CLAIMS ──");
                sb.Append(claims);
            }
            JwtOutput = sb.ToString().TrimEnd();

            // Verify only when a key is supplied and the token is signed (3 parts).
            string alg = ReadAlg(headerJson);
            if (parts.Length == 3)
            {
                string key = JwtKey.Trim();
                if (key.Length > 0)
                    JwtVerify = VerifySignature(parts, alg, ReadJsonString(headerJson, "kid"), key);
                else if (alg.Equals("none", StringComparison.OrdinalIgnoreCase))
                    JwtVerify = "⚠ alg=none — this token is UNSIGNED.";
                else
                    JwtVerify = $"Signature present (alg {alg}). Paste the secret / PEM public key to verify.";
            }
        }
        catch (Exception ex) { ErrorMessage = "JWT Error: " + ex.Message; }
    }

    // ---- decode / format ----

    private static byte[] B64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static string DecodeUtf8(string b64url) => Encoding.UTF8.GetString(B64UrlDecode(b64url));

    private static string Pretty(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            // Relaxed (IndentedJson): the default encoder showed a Persian "name" and every
            // ' < > & + in a claim as \uXXXX escapes. Capped: this runs on the UI thread, and a deeply nested
            // claim set indents up to ×64.
            return WriteJsonCapped(IndentedJson, w => doc.WriteTo(w), "Decoded JSON");
        }
        catch { return json; }   // not JSON (shouldn't happen for a valid JWT), or too big to indent — show raw
    }

    private static string ReadAlg(string headerJson) => ReadJsonString(headerJson, "alg");

    // A top-level string member of a JSON object; "" when it is missing, not a string, or not JSON.
    private static string ReadJsonString(string json, string name)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return JsonStr(doc.RootElement, name);
        }
        catch { return ""; }
    }

    private static string JsonStr(JsonElement obj, string name) =>
        obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";

    // Humanize the registered time/id claims (exp, nbf, iat, iss, aud, sub) with an expiry verdict.
    private static string DescribeClaims(string payloadJson)
    {
        var sb = new StringBuilder();
        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            var root = doc.RootElement;
            var now = DateTimeOffset.UtcNow;

            void Time(string key, string label)
            {
                if (!root.TryGetProperty(key, out var el) || el.ValueKind != JsonValueKind.Number) return;
                if (ClaimTime(el) is not { } dto)
                {
                    sb.AppendLine($"{label,-18}: {el.GetRawText()}  (not a date in seconds — milliseconds?)");
                    return;
                }
                // Invariant: a phone set to fa-IR / th-TH would otherwise print a Persian / Buddhist
                // calendar year in this ISO-looking field. Relative() lives in the Epoch partial; it
                // reads (now - t) as "ago" for a past t.
                sb.AppendLine($"{label,-18}: {dto.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture)}  ({Relative(now - dto)})");
            }
            void Str(string key, string label)
            {
                if (root.TryGetProperty(key, out var el))
                    sb.AppendLine($"{label,-18}: {(el.ValueKind == JsonValueKind.String ? el.GetString() : el.GetRawText())}");
            }

            Str("iss", "issuer (iss)");
            Str("sub", "subject (sub)");
            Str("aud", "audience (aud)");
            Time("iat", "issued (iat)");
            Time("nbf", "not-before (nbf)");
            Time("exp", "expires (exp)");

            // overall status
            if (root.TryGetProperty("exp", out var expEl) && ClaimTime(expEl) is { } expDto)
            {
                if (expDto < now) sb.AppendLine($"{"status",-18}: ✗ EXPIRED");
                else sb.AppendLine($"{"status",-18}: ✓ not expired");
            }
            if (root.TryGetProperty("nbf", out var nbfEl) && ClaimTime(nbfEl) is { } nbfDto && nbfDto > now)
                sb.AppendLine($"{"status",-18}: ⚠ NOT YET VALID (nbf in the future)");
        }
        catch { }
        return sb.ToString();
    }

    // A NumericDate (RFC 7519 §2): seconds since the epoch, fractions allowed. Null when it isn't one
    // DateTimeOffset can hold — e.g. milliseconds by mistake, which made FromUnixTimeSeconds throw
    // and the catch above silently drop that claim and every line after it (status included).
    private static DateTimeOffset? ClaimTime(JsonElement el) =>
        el.ValueKind == JsonValueKind.Number && el.TryGetDouble(out double s) && s is >= -62135596800d and < 253402300800d
            ? DateTimeOffset.FromUnixTimeSeconds((long)Math.Floor(s))
            : null;

    // ---- signature verification (HS / RS / PS / ES) ----

    // The key box takes an HMAC secret, PEM text (public key, PKCS#1, certificate) or a JWK / JWK Set.
    private static string VerifySignature(string[] parts, string alg, string kid, string key)
    {
        string a = alg.ToUpperInvariant();
        if (a == "NONE") return "⚠ alg=none — this token is UNSIGNED.";
        if (a.Length == 0) return "⚠ The header has no \"alg\" — nothing to verify against.";
        string family = a.Length == 5 && a[2..] is ("256" or "384" or "512") ? a[..2] : "";
        if (family is not ("HS" or "RS" or "PS" or "ES")) return $"⚠ Verify not supported for alg {alg}.";

        byte[] signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        byte[] sig;
        try { sig = B64UrlDecode(parts[2]); }
        catch { return "✗ Signature is not valid Base64Url."; }

        bool pem = key.Contains("-----BEGIN", StringComparison.Ordinal);
        string want = family switch { "HS" => "oct", "ES" => "EC", _ => "RSA" };   // JWK "kty" the alg needs
        try
        {
            using JsonDocument? jwks = pem ? null : ParseJwk(key);
            JsonElement? jwk = jwks is null ? null : PickJwk(jwks.RootElement, kid, want);
            string kty = jwk is { } k ? JsonStr(k, "kty") : "";

            if (family == "HS")
            {
                // Algorithm confusion: a token that says HS256 but was MACed with the server's PUBLIC key
                // text "verifies" against that same PEM / JWK. A public key is never an HMAC secret, and
                // a verifier that accepts one lets anyone forge tokens — so don't report VALID.
                if (pem || (jwks is not null && kty != "oct"))
                    return $"✗ alg={alg} but the key is a public key ({(pem ? "PEM" : "JWK")}) — classic algorithm-confusion attack; verification refused. "
                           + "An HMAC token is checked with the shared secret, never with a public key.";
                byte[] secret = jwk is { } oct ? B64UrlDecode(JsonStr(oct, "k")) : Encoding.UTF8.GetBytes(key);
                // A JWK without key material ({"kty":"oct"}, "k": "", a JWKS entry with no "k") gave an EMPTY HMAC key,
                // and a token anyone can MAC with an empty key then showed as VALID.
                if (secret.Length == 0)
                    return "✗ The JWK has no key material (\"k\" is missing or empty) — nothing to verify with. An empty HMAC key would let anyone forge the token.";
                byte[] computed = a switch
                {
                    "HS256" => HMACSHA256.HashData(secret, signingInput),
                    "HS384" => HMACSHA384.HashData(secret, signingInput),
                    _ => HMACSHA512.HashData(secret, signingInput),
                };
                return CryptographicOperations.FixedTimeEquals(sig, computed)
                    ? $"✓ Signature VALID  (HMAC {alg})"
                    : "✗ Signature INVALID  (wrong secret or tampered)";
            }

            if (!pem && jwks is null)
                return $"✗ alg={alg} is checked with the issuer's {want} public key — paste it as PEM (-----BEGIN PUBLIC KEY-----) "
                       + "or as a JWK. The key box holds neither (an HMAC secret?).";
            if (jwks is not null && kty != want)
                return jwk is null
                    ? $"✗ alg={alg} needs an {want} key — the JWK Set has none{(kid.Length > 0 ? $" (token kid \"{kid}\")" : "")}."
                    : $"✗ alg={alg} needs an {want} key, but the JWK is kty \"{kty}\".";

            if (family == "ES")
            {
                ECDsa ec;
                try { ec = pem ? EcFromPem(key) : EcFromJwk(jwk!.Value); }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
                { return $"✗ alg={alg} needs an EC public key — this {(pem ? "PEM" : "JWK")} can't be read as one ({ex.Message})"; }
                using (ec)
                {
                    // JWT ECDSA signatures are raw r‖s (IEEE P1363), which is what VerifyData expects here.
                    bool ok = ec.VerifyData(signingInput, sig, HashFor(a), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    return ok ? $"✓ Signature VALID  ({alg}, EC public key)" : "✗ Signature INVALID";
                }
            }

            RSA rsa;
            try { rsa = pem ? RsaFromPem(key) : RsaFromJwk(jwk!.Value); }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
            { return $"✗ alg={alg} needs an RSA public key — this {(pem ? "PEM" : "JWK")} can't be read as one ({ex.Message})"; }
            using (rsa)
            {
                var padding = family == "PS" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                bool ok = rsa.VerifyData(signingInput, sig, HashFor(a), padding);
                return ok ? $"✓ Signature VALID  ({alg}, RSA public key)" : "✗ Signature INVALID";
            }
        }
        catch (Exception ex) { return $"✗ Verify error: {ex.Message}"; }
    }

    // A JWK ({"kty":…}) or JWK Set ({"keys":[…]}); null for anything else, which is then a plain secret.
    private static JsonDocument? ParseJwk(string key)
    {
        if (!key.StartsWith('{')) return null;
        try
        {
            var doc = JsonDocument.Parse(key);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Object && (root.TryGetProperty("kty", out _) || root.TryGetProperty("keys", out _)))
                return doc;
            doc.Dispose();
        }
        catch (JsonException) { }
        return null;
    }

    // A single JWK as is; from a JWK Set the key named by the token's "kid", else the first of the right type.
    private static JsonElement? PickJwk(JsonElement root, string kid, string kty)
    {
        if (!root.TryGetProperty("keys", out var keys)) return root;
        if (keys.ValueKind != JsonValueKind.Array) return null;
        JsonElement? byType = null;
        foreach (var k in keys.EnumerateArray())
        {
            if (k.ValueKind != JsonValueKind.Object) continue;
            if (kid.Length > 0 && JsonStr(k, "kid") == kid) return k;
            if (byType is null && JsonStr(k, "kty") == kty) byType = k;
        }
        return byType;
    }

    // SubjectPublicKeyInfo / PKCS#1 / private-key PEM, or an X.509 certificate (what Auth0 and Firebase
    // publish), which ImportFromPem alone rejects with a cryptic "no supported key formats".
    private static RSA RsaFromPem(string pem)
    {
        if (pem.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            using var cert = X509Certificate2.CreateFromPem(pem);
            return cert.GetRSAPublicKey() ?? throw new CryptographicException("the certificate's key is not RSA");
        }
        var rsa = RSA.Create();
        try { rsa.ImportFromPem(pem); return rsa; }
        catch { rsa.Dispose(); throw; }
    }

    private static ECDsa EcFromPem(string pem)
    {
        if (pem.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            using var cert = X509Certificate2.CreateFromPem(pem);
            return cert.GetECDsaPublicKey() ?? throw new CryptographicException("the certificate's key is not EC");
        }
        var ec = ECDsa.Create();
        try { ec.ImportFromPem(pem); return ec; }
        catch { ec.Dispose(); throw; }
    }

    private static RSA RsaFromJwk(JsonElement jwk) => RSA.Create(new RSAParameters
    {
        Modulus = B64UrlDecode(JsonStr(jwk, "n")),
        Exponent = B64UrlDecode(JsonStr(jwk, "e")),
    });

    private static ECDsa EcFromJwk(JsonElement jwk) => ECDsa.Create(new ECParameters
    {
        Curve = JsonStr(jwk, "crv") switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            var crv => throw new CryptographicException($"unsupported curve \"{crv}\""),
        },
        Q = new ECPoint { X = B64UrlDecode(JsonStr(jwk, "x")), Y = B64UrlDecode(JsonStr(jwk, "y")) },
    });

    private static HashAlgorithmName HashFor(string alg) => alg[^3..] switch
    {
        "256" => HashAlgorithmName.SHA256,
        "384" => HashAlgorithmName.SHA384,
        "512" => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256,
    };
}
