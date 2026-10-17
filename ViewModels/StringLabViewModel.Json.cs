using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _jsonInput = string.Empty;
    [ObservableProperty] private string _jsonOutput = string.Empty;

    // Lenient fallback patterns (quote bare keys, 'single' → "double"). Linear patterns, but they
    // still get a timeout — they run over arbitrary pasted text.
    private static readonly Regex BareKeyRe = new(@"(?<![""'])\b([a-zA-Z0-9_]+)\b(?=\s*:)", RegexOptions.None, InternalRegexTimeout);
    private static readonly Regex SingleQuoteRe = new(@"'([^']*)'", RegexOptions.None, InternalRegexTimeout);

    [RelayCommand]
    private Task JsonAction(string mode)
    {
        string input = JsonInput;
        if (string.IsNullOrWhiteSpace(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("json", () => mode switch
        {
            "validate" => ValidateJson(input),
            "sort" => SortJsonKeys(input),
            // Whole input as ONE JSON string literal (e.g. to embed a JSON document in another).
            "escape" => EscapeAsJsonString(input),
            "unescape" => UnescapeJsonString(input),
            _ => ReformatJson(input, indented: mode == "format"),
        }, r => JsonOutput = r, "JSON Error: ");
    }

    private static string ReformatJson(string input, bool indented)
    {
        using var doc = ParseJsonLenient(input);
        return WriteJson(doc.RootElement, indented, sortKeys: false);
    }

    private static JsonDocument ParseJsonLenient(string input)
    {
        var parseOptions = new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip };
        try
        {
            // If the input is already valid JSON, format/minify it verbatim. Running the lenient
            // key-quoting heuristic below on valid JSON would corrupt string values that contain
            // "word: " (log lines, URLs, times), so only fall back to it when strict parsing fails.
            return JsonDocument.Parse(input, parseOptions);
        }
        catch (JsonException strictError)
        {
            // Lenient pass: quote bare object keys and turn 'single' into "double" quotes.
            string processed = BareKeyRe.Replace(input, @"""$1""");
            processed = SingleQuoteRe.Replace(processed, @"""$1""");
            try { return JsonDocument.Parse(processed, parseOptions); }
            catch (JsonException) { throw new FormatException(JsonErrorDetail(strictError, input)); }   // report the ORIGINAL position
        }
    }

    // Strict RFC 8259 check (no comments, no trailing commas) with a short structural summary.
    private static string ValidateJson(string input)
    {
        try
        {
            using var doc = JsonDocument.Parse(input);
            var root = doc.RootElement;
            string shape = root.ValueKind switch
            {
                JsonValueKind.Object => $"object with {root.EnumerateObject().Count():N0} top-level key(s)",
                JsonValueKind.Array => $"array with {root.GetArrayLength():N0} item(s)",
                _ => root.ValueKind.ToString().ToLowerInvariant() + " value",
            };
            return $"✓ Valid JSON — {shape}, max depth {Depth(root)}.";
        }
        catch (JsonException ex)
        {
            return "✗ Invalid JSON" + Environment.NewLine + JsonErrorDetail(ex, input);
        }
    }

    private static int Depth(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.Object => 1 + el.EnumerateObject().Select(p => Depth(p.Value)).DefaultIfEmpty(0).Max(),
        JsonValueKind.Array => 1 + el.EnumerateArray().Select(Depth).DefaultIfEmpty(0).Max(),
        _ => 0,
    };

    private static string SortJsonKeys(string input)
    {
        using var doc = ParseJsonLenient(input);
        return WriteJson(doc.RootElement, indented: true, sortKeys: true);
    }

    // JsonDocument caps nesting at 64 levels, so the recursion below is bounded. Indented output pays up to 128 spaces
    // per value, so it is written against the output ceiling.
    private static string WriteJson(JsonElement root, bool indented, bool sortKeys)
        => WriteJsonCapped(indented ? IndentedJson : CompactJson, w =>
        {
            if (sortKeys) WriteSorted(root, w);
            else root.WriteTo(w);
        }, "Formatted JSON");

    // Keys ordered ordinally at every level; OrderBy is stable, so duplicate keys keep their order.
    // Arrays keep their element order (it is meaningful).
    private static void WriteSorted(JsonElement el, Utf8JsonWriter w)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                w.WriteStartObject();
                foreach (var p in el.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    w.WritePropertyName(p.Name);
                    WriteSorted(p.Value, w);
                }
                w.WriteEndObject();
                break;
            case JsonValueKind.Array:
                w.WriteStartArray();
                foreach (var item in el.EnumerateArray()) WriteSorted(item, w);
                w.WriteEndArray();
                break;
            default:
                el.WriteTo(w);
                break;
        }
    }

    private static string EscapeAsJsonString(string input)
    {
        EnsureOutputSize(EscapedSizeBound(input) + 2, "Escaped output");
        return "\"" + TextEscape.JsonEscape(input) + "\"";
    }

    // A JSON string literal ("{\"a\":1}") → its text; if that text is itself JSON, pretty-print it.
    private static string UnescapeJsonString(string input)
    {
        string text = TextEscape.JsonUnescape(input);
        string t = text.TrimStart();
        if (t.StartsWith('{') || t.StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                return WriteJson(doc.RootElement, indented: true, sortKeys: false);
            }
            catch (JsonException) { }   // not JSON after all — return the plain text
        }
        return text;
    }
}
