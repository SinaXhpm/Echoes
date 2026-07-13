using System;
using System.Security.Cryptography;
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
                if (JwtKey.Trim().Length > 0)
                    JwtVerify = VerifySignature(parts, alg, JwtKey.Trim());
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
            using var ms = new System.IO.MemoryStream();
            using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
                doc.WriteTo(w);
            return Encoding.UTF8.GetString(ms.ToArray());
        }
        catch { return json; }   // not JSON (shouldn't happen for a valid JWT) — show raw
    }

    private static string ReadAlg(string headerJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(headerJson);
            return doc.RootElement.TryGetProperty("alg", out var a) ? a.GetString() ?? "" : "";
        }
        catch { return ""; }
    }

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
                if (root.TryGetProperty(key, out var el) && el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out long unix))
                {
                    var dto = DateTimeOffset.FromUnixTimeSeconds(unix);
                    // Relative() lives in the Epoch partial; it reads (now - t) as "ago" for a past t.
                    sb.AppendLine($"{label,-18}: {dto:yyyy-MM-dd HH:mm:ss 'UTC'}  ({Relative(now - dto)})");
                }
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
            if (root.TryGetProperty("exp", out var expEl) && expEl.ValueKind == JsonValueKind.Number && expEl.TryGetInt64(out long exp))
            {
                var expDto = DateTimeOffset.FromUnixTimeSeconds(exp);
                if (expDto < now) sb.AppendLine($"{"status",-18}: ✗ EXPIRED");
                else sb.AppendLine($"{"status",-18}: ✓ not expired");
            }
            if (root.TryGetProperty("nbf", out var nbfEl) && nbfEl.ValueKind == JsonValueKind.Number && nbfEl.TryGetInt64(out long nbf)
                && DateTimeOffset.FromUnixTimeSeconds(nbf) > now)
                sb.AppendLine($"{"status",-18}: ⚠ NOT YET VALID (nbf in the future)");
        }
        catch { }
        return sb.ToString();
    }

    // ---- signature verification (HS / RS / PS / ES) ----

    private static string VerifySignature(string[] parts, string alg, string key)
    {
        string a = alg.ToUpperInvariant();
        byte[] signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        byte[] sig;
        try { sig = B64UrlDecode(parts[2]); }
        catch { return "✗ Signature is not valid Base64Url."; }

        try
        {
            if (a.StartsWith("HS", StringComparison.Ordinal))
            {
                using HMAC hmac = a switch
                {
                    "HS256" => new HMACSHA256(Encoding.UTF8.GetBytes(key)),
                    "HS384" => new HMACSHA384(Encoding.UTF8.GetBytes(key)),
                    "HS512" => new HMACSHA512(Encoding.UTF8.GetBytes(key)),
                    _ => throw new NotSupportedException(alg),
                };
                byte[] computed = hmac.ComputeHash(signingInput);
                return CryptographicOperations.FixedTimeEquals(sig, computed)
                    ? $"✓ Signature VALID  (HMAC {alg})"
                    : $"✗ Signature INVALID  (wrong secret or tampered)";
            }
            if (a.StartsWith("RS", StringComparison.Ordinal) || a.StartsWith("PS", StringComparison.Ordinal))
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(key);
                var padding = a.StartsWith("PS", StringComparison.Ordinal) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                bool ok = rsa.VerifyData(signingInput, sig, HashFor(a), padding);
                return ok ? $"✓ Signature VALID  ({alg}, RSA public key)" : "✗ Signature INVALID";
            }
            if (a.StartsWith("ES", StringComparison.Ordinal))
            {
                using var ec = ECDsa.Create();
                ec.ImportFromPem(key);
                // JWT ECDSA signatures are raw r‖s (IEEE P1363), which is what VerifyData expects here.
                bool ok = ec.VerifyData(signingInput, sig, HashFor(a), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                return ok ? $"✓ Signature VALID  ({alg}, EC public key)" : "✗ Signature INVALID";
            }
            if (a == "NONE") return "⚠ alg=none — this token is UNSIGNED.";
            return $"⚠ Verify not supported for alg {alg}.";
        }
        catch (Exception ex) { return $"✗ Verify error: {ex.Message}"; }
    }

    private static HashAlgorithmName HashFor(string alg) => alg[^3..] switch
    {
        "256" => HashAlgorithmName.SHA256,
        "384" => HashAlgorithmName.SHA384,
        "512" => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256,
    };
}
