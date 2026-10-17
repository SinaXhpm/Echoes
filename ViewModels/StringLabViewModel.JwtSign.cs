using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

// JWT SIGN: build a token from header JSON + payload JSON + a shared secret (HS256/384/512).
public partial class StringLabViewModel
{
    private const string DefaultJwtHeader = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

    [ObservableProperty] private string _jwtSignHeader = DefaultJwtHeader;
    [ObservableProperty] private string _jwtSignPayload = string.Empty;
    [ObservableProperty] private string _jwtSignSecret = string.Empty;
    [ObservableProperty] private string _jwtSignOutput = string.Empty;

    // Relaxed: keep non-ASCII claim values readable instead of \uXXXX (both are valid JSON).
    private static readonly JsonWriterOptions CompactJson = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static readonly JsonWriterOptions IndentedJson = new() { Indented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    [RelayCommand]
    private void SignJwt()
    {
        try
        {
            ResetError();
            JwtSignOutput = string.Empty;

            string header = ParseJsonObject(string.IsNullOrWhiteSpace(JwtSignHeader) ? DefaultJwtHeader : JwtSignHeader, "Header", indented: false);
            string payload = ParseJsonObject(string.IsNullOrWhiteSpace(JwtSignPayload) ? "{}" : JwtSignPayload, "Payload", indented: false);
            string alg = ReadAlg(header);
            if (alg.Length == 0) { ErrorMessage = "The header needs an \"alg\" — HS256, HS384 or HS512."; return; }
            if (alg.ToUpperInvariant() is not ("HS256" or "HS384" or "HS512"))
            {
                ErrorMessage = $"JWT Sign: alg \"{alg}\" isn't supported here — use HS256, HS384 or HS512 with a shared secret.";
                return;
            }

            string signingInput = ToBase64Url(Encoding.UTF8.GetBytes(header)) + "." + ToBase64Url(Encoding.UTF8.GetBytes(payload));

            // Only signed tokens are produced; "none" (or any non-HS alg) falls through to the
            // unsupported-alg error below.
            byte[]? key = JwtSignSecret.Length > 0 ? Encoding.UTF8.GetBytes(JwtSignSecret) : null;
            if (key is null) { ErrorMessage = "Enter the HMAC secret to sign with."; return; }

            byte[] data = Encoding.ASCII.GetBytes(signingInput);
            byte[] sig = alg.ToUpperInvariant() switch
            {
                "HS256" => HMACSHA256.HashData(key, data),
                "HS384" => HMACSHA384.HashData(key, data),
                "HS512" => HMACSHA512.HashData(key, data),
                _ => throw new NotSupportedException($"alg \"{alg}\" can't be signed here — only HS256 / HS384 / HS512 (shared secret) are supported."),
            };
            JwtSignOutput = signingInput + "." + ToBase64Url(sig);
        }
        catch (Exception ex) { ErrorMessage = "JWT Sign: " + ex.Message; }
    }

    // HS256 / HS384 / HS512 buttons: rewrite the header's "alg", keeping every other field.
    [RelayCommand]
    private void JwtSetAlg(string alg)
    {
        try
        {
            ResetError();
            string src = string.IsNullOrWhiteSpace(JwtSignHeader) ? DefaultJwtHeader : JwtSignHeader;
            JwtSignHeader = RewriteJsonObject(src, "Header", indented: false, w =>
            {
                w.WriteString("alg", alg);
            }, "alg");
        }
        catch (Exception ex) { ErrorMessage = "JWT Sign: " + ex.Message; }
    }

    // "+ iat / exp": stamp issued-at = now and expiry = now + 1 h into the payload.
    [RelayCommand]
    private void JwtAddTimes()
    {
        try
        {
            ResetError();
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string src = string.IsNullOrWhiteSpace(JwtSignPayload) ? "{}" : JwtSignPayload;
            JwtSignPayload = RewriteJsonObject(src, "Payload", indented: true, w =>
            {
                w.WriteNumber("iat", now);
                w.WriteNumber("exp", now + 3600);
            }, "iat", "exp");
        }
        catch (Exception ex) { ErrorMessage = "JWT Sign: " + ex.Message; }
    }

    // Validates that `json` is a JSON object and re-serialises it (compact or indented).
    private static string ParseJsonObject(string json, string what, bool indented)
        => RewriteJsonObject(json, what, indented, null);

    // Re-serialises a JSON object, writing `prepend` first and dropping the `replaced` keys from the
    // original. Throws a FormatException that names the input and the line/column of a syntax error.
    private static string RewriteJsonObject(string json, string what, bool indented, Action<Utf8JsonWriter>? prepend, params string[] replaced)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException ex) { throw new FormatException($"{what} is not valid JSON — {JsonErrorDetail(ex, json)}"); }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                throw new FormatException($"{what} must be a JSON object {{ … }}.");

            var root = doc.RootElement;
            return WriteJsonCapped(indented ? IndentedJson : CompactJson, w =>
            {
                w.WriteStartObject();
                prepend?.Invoke(w);
                foreach (var p in root.EnumerateObject())
                {
                    if (Array.IndexOf(replaced, p.Name) >= 0) continue;
                    p.WriteTo(w);
                }
                w.WriteEndObject();
            }, what);
        }
    }

    // "line 3, column 14: 'x' is an invalid start of a value." — JsonException positions are
    // zero-based (people count from 1) and its Message repeats them in a noisier form, so trim that.
    // BytePositionInLine counts UTF-8 BYTES: given the parsed text, it is turned into a character
    // column, or a line holding four 2-byte characters (8 bytes, 4 chars) pointed 4 columns past the error.
    private static string JsonErrorDetail(JsonException ex, string? json = null)
    {
        string reason = ex.Message;
        int cut = reason.IndexOf(" LineNumber:", StringComparison.Ordinal);
        if (cut > 0) reason = reason[..cut];
        if (ex.LineNumber is not long line) return reason;
        long column = ex.BytePositionInLine ?? 0;
        if (json != null) column = CharColumn(json, line, column);
        return $"line {line + 1}, column {column + 1}: {reason}";
    }

    // Characters (a surrogate pair counts once) covered by the first `bytes` UTF-8 bytes of the
    // zero-based `line` — Utf8JsonReader only counts '\n' as a line break.
    private static long CharColumn(string json, long line, long bytes)
    {
        int i = 0;
        for (long l = 0; l < line; l++)
        {
            i = json.IndexOf('\n', i);
            if (i < 0) return bytes;
            i++;
        }
        long chars = 0;
        while (bytes > 0 && i < json.Length)
        {
            char c = json[i];
            bool pair = char.IsHighSurrogate(c) && i + 1 < json.Length && char.IsLowSurrogate(json[i + 1]);
            bytes -= c < 0x80 ? 1 : c < 0x800 ? 2 : pair ? 4 : 3;
            i += pair ? 2 : 1;
            chars++;
        }
        return chars;
    }
}
