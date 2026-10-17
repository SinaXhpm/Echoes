using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _convertInput = string.Empty;
    [ObservableProperty] private string _convertOutput = string.Empty;

    [RelayCommand]
    private Task ConvertAction(string mode)
    {
        string input = ConvertInput;
        if (string.IsNullOrWhiteSpace(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("convert", () => mode switch
        {
            "json2yaml" => JsonToYaml(input),
            "yaml2json" => YamlToJson(input),
            "json2csv" => JsonToCsv(input),
            "csv2json" => CsvToJson(input),
            "csv2md" => CsvToMarkdown(input),
            "qs2json" => QueryToJson(input),
            "json2qs" => JsonToQuery(input),
            _ => input
        }, r => ConvertOutput = r, "Convert Error: ");
    }

    // TSV if the header line has a tab and no comma (spreadsheet copy-paste), CSV otherwise.
    private static char DetectDelimiter(string text)
    {
        int nl = text.IndexOf('\n');
        string first = nl >= 0 ? text[..nl] : text;
        return first.Contains('\t') && !first.Contains(',') ? '\t' : ',';
    }

    // ---------- CSV / TSV -> Markdown table ----------
    private static string CsvToMarkdown(string csv)
    {
        var rows = ParseCsv(csv, DetectDelimiter(csv));
        if (rows.Count == 0) return string.Empty;
        int cols = rows.Max(r => r.Count);
        // Every row is written with every column (" | " each): one wide line over many short ones multiplied the input
        // (11 KB → 6.8 M chars), so refuse up front what can't fit.
        EnsureOutputSize((long)rows.Count * cols * 3, "Markdown table");

        static string Cell(string s) => s.Replace("|", "\\|").Replace("\r", "").Replace("\n", "<br>").Trim();
        string Line(List<string> r) => "| " + string.Join(" | ", Enumerable.Range(0, cols).Select(c => c < r.Count ? Cell(r[c]) : "")) + " |";

        var sb = new StringBuilder();
        sb.AppendLine(Line(rows[0]));
        sb.AppendLine("|" + string.Concat(Enumerable.Repeat(" --- |", cols)));
        for (int i = 1; i < rows.Count; i++) sb.AppendLine(Line(rows[i]));
        return sb.ToString().TrimEnd();
    }

    // ---------- query string <-> JSON ----------

    // Accepts "a=1&b=2", "?a=1&b=2" or a full URL (only its query is used). Repeated keys → array.
    private static string QueryToJson(string input)
    {
        string q = input.Trim();
        // The query starts after the first '?' of a URL / "?a=1" — but in a bare "a=1&next=/x?y=2" that
        // '?' sits inside a value, and cutting there dropped every pair before it.
        int qm = q.IndexOf('?');
        int firstPair = q.IndexOfAny(new[] { '=', '&' });
        if (qm >= 0 && (q.Contains("://", StringComparison.Ordinal) || firstPair < 0 || qm < firstPair)) q = q[(qm + 1)..];
        int hash = q.IndexOf('#');
        if (hash >= 0) q = q[..hash];

        // Keys in first-seen order; the dictionary finds a repeat in O(1) — a list search per key made 40 K distinct keys
        // take 9 s (quadratic) with the Convert tool locked meanwhile.
        var map = new List<(string Key, List<string> Values)>();
        var index = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var pair in q.Split(new[] { '&', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            string key = FormDecode(eq >= 0 ? pair[..eq] : pair).Trim();
            string val = eq >= 0 ? FormDecode(pair[(eq + 1)..]) : string.Empty;
            if (key.Length == 0) continue;
            if (index.TryGetValue(key, out int idx)) map[idx].Values.Add(val);
            else
            {
                index[key] = map.Count;
                map.Add((key, new List<string> { val }));
            }
        }

        return WriteJsonCapped(IndentedJson, w =>
        {
            w.WriteStartObject();
            foreach (var (key, values) in map)
            {
                if (values.Count == 1) { w.WriteString(key, values[0]); continue; }
                w.WriteStartArray(key);
                foreach (var v in values) w.WriteStringValue(v);
                w.WriteEndArray();
            }
            w.WriteEndObject();
        }, "JSON output");
    }

    // Flat JSON object → a=1&b=2. Arrays repeat the key; nested objects are sent as JSON text;
    // null → bare key. Encoded per RFC 3986 (%20), which every server accepts.
    private static string JsonToQuery(string json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true });
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new FormatException("Query-string export expects a JSON object { \"key\": value, … }.");

        var parts = new List<string>();
        void Add(string key, JsonElement v)
        {
            string k = Uri.EscapeDataString(key);
            switch (v.ValueKind)
            {
                case JsonValueKind.Null: parts.Add(k); break;
                case JsonValueKind.String: parts.Add(k + "=" + Uri.EscapeDataString(v.GetString() ?? "")); break;
                default: parts.Add(k + "=" + Uri.EscapeDataString(v.GetRawText())); break;
            }
        }
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (p.Value.ValueKind == JsonValueKind.Array)
                foreach (var item in p.Value.EnumerateArray()) Add(p.Name, item);
            else Add(p.Name, p.Value);
        }
        return string.Join("&", parts);
    }

    // ---------- JSON -> YAML ----------
    private static string JsonToYaml(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder();
        WriteYaml(doc.RootElement, sb, 0, false);
        return sb.ToString().TrimEnd();
    }

    // Every line pays its indentation (up to 128 spaces at depth 64): nested around many values, that multiplied the
    // input (600 KB → 38 M chars), so each line is checked against the output ceiling.
    private static void WriteYaml(JsonElement el, StringBuilder sb, int indent, bool inline)
    {
        string pad = new string(' ', indent * 2);
        if (IsScalar(el)) { sb.AppendLine($"{pad}{YamlScalar(el)}"); CheckOutput(sb, "YAML output"); return; }   // incl. a top-level {} / []
        if (el.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in el.EnumerateObject())
            {
                if (IsScalar(p.Value)) sb.AppendLine($"{pad}{YamlKey(p.Name)}: {YamlScalar(p.Value)}");
                else { sb.AppendLine($"{pad}{YamlKey(p.Name)}:"); WriteYaml(p.Value, sb, indent + 1, false); }
                CheckOutput(sb, "YAML output");
            }
        }
        else
        {
            foreach (var item in el.EnumerateArray())
            {
                if (IsScalar(item)) sb.AppendLine($"{pad}- {YamlScalar(item)}");
                else { sb.AppendLine($"{pad}-"); WriteYaml(item, sb, indent + 1, false); }
                CheckOutput(sb, "YAML output");
            }
        }
    }

    // An empty {} / [] counts as a scalar: it has no block form (a bare "key:" reads back as null),
    // so it is written in flow style.
    private static bool IsScalar(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.Object => !el.EnumerateObject().Any(),
        JsonValueKind.Array => el.GetArrayLength() == 0,
        _ => true,
    };

    private static string YamlScalar(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => YamlQuote(el.GetString()!),
        JsonValueKind.Object => "{}",
        JsonValueKind.Array => "[]",
        JsonValueKind.Number => el.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "null",
        _ => el.GetRawText()
    };

    // A double-quoted YAML scalar. Line breaks and control characters must be escaped: written raw, a
    // YAML parser folds "a\nb" into "a b", and C0/C1 controls (and NEL, LS, PS) aren't allowed at all.
    private static string YamlQuote(string s)
    {
        var sb = new StringBuilder(s.Length + 2).Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < ' ' || (int)c is (>= 0x7F and <= 0x9F) or 0x2028 or 0x2029 or 0xFFFE or 0xFFFF)
                        sb.Append("\\u").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    // Plain words a YAML loader reads as booleans / null instead of strings (YAML 1.1 and 1.2).
    private static readonly HashSet<string> YamlReservedWords = new(StringComparer.OrdinalIgnoreCase)
        { "true", "false", "yes", "no", "on", "off", "y", "n", "null" };

    // A key stays plain only when YAML reads it back as the same string; anything else (": " / " #"
    // inside, a leading "-", "", "123", "true", …) is quoted — written bare, it broke the document.
    private static string YamlKey(string key)
    {
        bool plain = key.Length > 0 && (char.IsLetter(key[0]) || key[0] == '_') && key[^1] != ' '
                     && key.All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or ' ' or '/' or '@' or '+' or '(' or ')')
                     && !YamlReservedWords.Contains(key);
        return plain ? key : YamlQuote(key);
    }

    // ---------- JSON -> CSV ----------
    private static string JsonToCsv(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            throw new Exception("CSV export expects a JSON array of objects.");

        var rows = doc.RootElement.EnumerateArray().ToList();
        var headers = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);   // a list search per key was quadratic
        foreach (var row in rows)
            if (row.ValueKind == JsonValueKind.Object)
                foreach (var p in row.EnumerateObject())
                    if (seen.Add(p.Name)) headers.Add(p.Name);
        // Every row gets every column (a comma each): objects that each bring new keys make rows × columns cells
        // (71 KB → 36 M chars), so refuse up front what can't fit.
        EnsureOutputSize((long)(rows.Count + 1) * Math.Max(1, headers.Count), "CSV output");

        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", headers.Select(CsvEscape)));
        foreach (var row in rows)
        {
            var cells = headers.Select(h =>
                row.ValueKind == JsonValueKind.Object && row.TryGetProperty(h, out var v)
                    ? CsvEscape(v.ValueKind == JsonValueKind.String ? v.GetString()! : v.GetRawText())
                    : "");
            sb.AppendLine(string.Join(",", cells));
        }
        return sb.ToString().TrimEnd();
    }

    private static string CsvEscape(string s)
    {
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n') || s.Contains('\r'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }

    // ---------- CSV -> JSON ----------
    private static string CsvToJson(string csv)
    {
        var rows = ParseCsv(csv, DetectDelimiter(csv));
        if (rows.Count < 1) return "[]";

        var headers = rows[0];
        // Every row is written with every header ("name": "", each): a wide header over many short rows multiplied the
        // input (11 KB → 27.6 M chars), so refuse up front what can't fit.
        long perRow = 8;
        foreach (var h in headers) perRow += h.Length + 8;
        EnsureOutputSize((rows.Count - 1) * perRow, "JSON output");
        var sb = new StringBuilder();
        sb.AppendLine("[");
        for (int r = 1; r < rows.Count; r++)
        {
            var cells = rows[r];
            sb.Append("  {");
            for (int c = 0; c < headers.Count; c++)
            {
                string val = c < cells.Count ? cells[c] : "";
                sb.Append($"\"{JsonEsc(headers[c])}\": \"{JsonEsc(val)}\"");
                if (c < headers.Count - 1) sb.Append(", ");
            }
            sb.Append('}');
            sb.AppendLine(r < rows.Count - 1 ? "," : "");
        }
        sb.Append(']');
        return sb.ToString();
    }

    // Relaxed, like every other JSON String Lab writes: the default encoder turned every non-ASCII
    // char (Persian, accents…) and ' < > & + into \uXXXX escapes — valid JSON, but unreadable.
    private static string JsonEsc(string s)
        => JsonEncodedText.Encode(s, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString();

    private static List<List<string>> ParseCsv(string csv, char delimiter = ',')
    {
        var result = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        bool inQuotes = false;
        csv = csv.Replace("\r\n", "\n").Replace("\r", "\n");

        for (int i = 0; i < csv.Length; i++)
        {
            char ch = csv[i];
            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (i + 1 < csv.Length && csv[i + 1] == '"') { field.Append('"'); i++; }
                    else inQuotes = false;
                }
                else field.Append(ch);
            }
            else
            {
                if (ch == delimiter) { row.Add(field.ToString()); field.Clear(); continue; }
                switch (ch)
                {
                    case '"': inQuotes = true; break;
                    case '\n':
                        row.Add(field.ToString()); field.Clear();
                        result.Add(row); row = new List<string>();
                        break;
                    default: field.Append(ch); break;
                }
            }
        }
        if (field.Length > 0 || row.Count > 0) { row.Add(field.ToString()); result.Add(row); }
        return result.Where(r => r.Count > 1 || (r.Count == 1 && r[0].Length > 0)).ToList();
    }

    // ---------- YAML -> JSON (common subset) ----------
    private static string YamlToJson(string yaml)
    {
        var lines = new List<(int indent, string text)>();
        foreach (var raw in yaml.Replace("\r\n", "\n").Split('\n'))
        {
            string noComment = StripYamlComment(raw);
            if (string.IsNullOrWhiteSpace(noComment)) continue;
            if (noComment.TrimEnd() is "---" or "...") continue;   // document start / end markers
            int indent = noComment.Length - noComment.TrimStart(' ').Length;
            lines.Add((indent, noComment.Trim()));
        }
        if (lines.Count == 0) return "{}";

        var sb = new StringBuilder();
        // A lone scalar document ("text", 42, [] or {} — what JsonToYaml writes for such a root).
        if (lines.Count == 1 && !IsListItem(lines[0].text) && FindColon(lines[0].text) < 0)
        {
            new YScalar(lines[0].text).WriteJson(sb, 0);
            return sb.ToString();
        }

        int pos = 0;
        var node = ParseYaml(lines, ref pos, lines[0].indent, 0);
        // Lines the subset parser can't place (block scalars "|" / ">", multi-line values, odd
        // indentation) used to be dropped silently together with everything after them.
        if (pos < lines.Count)
            throw new FormatException($"can't convert the line \"{lines[pos].text}\" — block scalars (| >), multi-line values and inconsistent indentation aren't supported.");
        node.WriteJson(sb, 0);
        return sb.ToString();
    }

    private static string StripYamlComment(string line)
    {
        bool inStr = false;
        char q = '\0';
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inStr)
            {
                if (c == '\\' && q == '"') i++;                                                   // \" stays inside "…"
                else if (c == '\'' && q == '\'' && i + 1 < line.Length && line[i + 1] == '\'') i++;   // '' stays inside '…'
                else if (c == q) inStr = false;
            }
            // A quote only opens a quoted scalar at its start ("don't # x" is plain text plus a comment).
            else if (c is '"' or '\'' && (i == 0 || line[i - 1] is ' ' or '\t')) { inStr = true; q = c; }
            else if (c == '#' && (i == 0 || line[i - 1] is ' ' or '\t')) return line[..i];
        }
        return line;
    }

    // "- x", or a bare "-" whose item is the deeper-indented block below (how JsonToYaml writes an
    // object or array inside an array). Lines are trimmed, so "- " never survives with its space.
    private static bool IsListItem(string text) => text == "-" || text.StartsWith("- ", StringComparison.Ordinal);

    // The text of a quoted scalar: "…" with its backslash escapes decoded, '…' with '' for a quote.
    private static string YamlUnquote(string s)
    {
        if (s.Length >= 2 && s[0] == '"' && s[^1] == '"') return TextEscape.BackslashUnescape(s[1..^1]);
        if (s.Length >= 2 && s[0] == '\'' && s[^1] == '\'') return s[1..^1].Replace("''", "'");
        return s;
    }

    private static YNode ParseYaml(List<(int indent, string text)> lines, ref int pos, int indent, int depth)
    {
        // Bail out well before a genuine stack overflow (which is uncatchable and would kill the app)
        // on pathologically nested input. The Convert() caller catches this and shows a friendly error.
        if (depth > 128) throw new InvalidOperationException("YAML nesting is too deep.");

        if (IsListItem(lines[pos].text))
        {
            var list = new YList();
            while (pos < lines.Count && lines[pos].indent == indent && IsListItem(lines[pos].text))
            {
                string text = lines[pos].text;
                string item = text[1..].Trim();
                if (item.Length == 0)
                {
                    pos++;
                    if (pos < lines.Count && lines[pos].indent > indent)
                        list.Items.Add(ParseYaml(lines, ref pos, lines[pos].indent, depth + 1));
                    else list.Items.Add(new YScalar(""));
                }
                else if (LooksLikeKey(item) || IsListItem(item))
                {
                    // "- key: v" / "- - x": the item is a map / list whose first line starts right after
                    // the dash. Re-read this line at that column, so the item's other lines (indented to
                    // the same column) and any nested values below them parse like any other block.
                    int col = indent + text.Length - text[1..].TrimStart().Length;
                    lines[pos] = (col, item);
                    list.Items.Add(ParseYaml(lines, ref pos, col, depth + 1));
                }
                else { pos++; list.Items.Add(new YScalar(item)); }
            }
            return list;
        }

        var topMap = new YMap();
        while (pos < lines.Count && lines[pos].indent == indent && !IsListItem(lines[pos].text))
        {
            if (!HandleMapLine(lines, ref pos, topMap, depth)) break;
        }
        return topMap;
    }

    private static bool HandleMapLine(List<(int indent, string text)> lines, ref int pos, YMap map, int depth)
    {
        var (ind, text) = lines[pos];
        int colon = FindColon(text);
        if (colon < 0) { pos++; return true; }

        string key = YamlUnquote(text[..colon].Trim());
        string val = text[(colon + 1)..].Trim();
        pos++;

        if (val.Length == 0)
        {
            // The value is the deeper-indented block below — or a list at the SAME indent
            // ("key:\n- a\n- b"), the compact style kubectl and PyYAML write; that list was dropped.
            if (pos < lines.Count && (lines[pos].indent > ind || (lines[pos].indent == ind && IsListItem(lines[pos].text))))
                map.Items.Add((key, ParseYaml(lines, ref pos, lines[pos].indent, depth + 1)));
            else
                map.Items.Add((key, new YScalar("")));
        }
        else
        {
            map.Items.Add((key, new YScalar(val)));
        }
        return true;
    }

    private static bool LooksLikeKey(string text) => FindColon(text) >= 0;

    // Same quoting rules as StripYamlComment, so a ": " inside "…" / '…' (escapes included) is no key.
    private static int FindColon(string text)
    {
        bool inStr = false; char q = '\0';
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (inStr)
            {
                if (c == '\\' && q == '"') i++;
                else if (c == '\'' && q == '\'' && i + 1 < text.Length && text[i + 1] == '\'') i++;
                else if (c == q) inStr = false;
            }
            else if (c is '"' or '\'' && (i == 0 || text[i - 1] is ' ' or '\t')) { inStr = true; q = c; }
            else if (c == ':' && (i == text.Length - 1 || text[i + 1] == ' ')) return i;
        }
        return -1;
    }

    private abstract class YNode { public abstract void WriteJson(StringBuilder sb, int indent); }

    private sealed class YScalar : YNode
    {
        // Exact JSON number grammar: optional sign, no leading zeros, optional fraction/exponent.
        private static readonly System.Text.RegularExpressions.Regex JsonNumberRe =
            new(@"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$",
                System.Text.RegularExpressions.RegexOptions.Compiled, InternalRegexTimeout);

        private readonly string _raw;
        public YScalar(string raw) => _raw = raw;

        public override void WriteJson(StringBuilder sb, int indent)
        {
            var v = _raw;
            if (v.Length == 0 || v == "null" || v == "~") { sb.Append("null"); return; }
            if (v == "true" || v == "false") { sb.Append(v); return; }
            if (v is "{}" or "[]") { sb.Append(v); return; }   // empty flow collections (JsonToYaml writes them)
            // Quoted: decode the escapes ("a\"b" is a"b, 'it''s' is it's) — they were copied through
            // verbatim, so JSON -> YAML -> JSON turned say "hi" into say \"hi\". A lone '"' is no quoting.
            if (v.Length >= 2 && ((v[0] == '"' && v[^1] == '"') || (v[0] == '\'' && v[^1] == '\'')))
            { sb.Append('"').Append(JsonEsc(YamlUnquote(v))).Append('"'); return; }
            // Only emit an unquoted number when the token is itself valid JSON-number syntax. Tokens that
            // parse in .NET but aren't legal JSON (leading zeros "08", ".5", "5.", "+5", "1,000",
            // "Infinity"/"NaN") must be quoted, or the output is invalid JSON.
            if (JsonNumberRe.IsMatch(v)) { sb.Append(v); return; }
            sb.Append('"').Append(JsonEsc(v)).Append('"');
        }
    }

    // Indentation grows with the depth on every line, and "- - - … x" nests one level per two characters of input
    // (484 KB → 59 M chars), so each line is checked against the output ceiling.
    private sealed class YMap : YNode
    {
        public readonly List<(string, YNode)> Items = new();
        public override void WriteJson(StringBuilder sb, int indent)
        {
            if (Items.Count == 0) { sb.Append("{}"); return; }
            string pad = new string(' ', (indent + 1) * 2);
            sb.AppendLine("{");
            for (int i = 0; i < Items.Count; i++)
            {
                sb.Append(pad).Append('"').Append(JsonEsc(Items[i].Item1)).Append("\": ");
                Items[i].Item2.WriteJson(sb, indent + 1);
                sb.AppendLine(i < Items.Count - 1 ? "," : "");
                CheckOutput(sb, "JSON output");
            }
            sb.Append(new string(' ', indent * 2)).Append('}');
        }
    }

    private sealed class YList : YNode
    {
        public readonly List<YNode> Items = new();
        public override void WriteJson(StringBuilder sb, int indent)
        {
            if (Items.Count == 0) { sb.Append("[]"); return; }
            string pad = new string(' ', (indent + 1) * 2);
            sb.AppendLine("[");
            for (int i = 0; i < Items.Count; i++)
            {
                sb.Append(pad);
                Items[i].WriteJson(sb, indent + 1);
                sb.AppendLine(i < Items.Count - 1 ? "," : "");
                CheckOutput(sb, "JSON output");
            }
            sb.Append(new string(' ', indent * 2)).Append(']');
        }
    }
}
