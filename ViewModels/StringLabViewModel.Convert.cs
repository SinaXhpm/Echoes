using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _convertInput = string.Empty;
    [ObservableProperty] private string _convertOutput = string.Empty;

    [RelayCommand]
    private void ConvertAction(string mode)
    {
        try
        {
            ResetError();
            if (string.IsNullOrWhiteSpace(ConvertInput)) return;

            ConvertOutput = mode switch
            {
                "json2yaml" => JsonToYaml(ConvertInput),
                "yaml2json" => YamlToJson(ConvertInput),
                "json2csv" => JsonToCsv(ConvertInput),
                "csv2json" => CsvToJson(ConvertInput),
                _ => ConvertInput
            };
        }
        catch (Exception ex) { ErrorMessage = $"Convert Error: {ex.Message}"; }
    }

    // ---------- JSON -> YAML ----------
    private static string JsonToYaml(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var sb = new StringBuilder();
        WriteYaml(doc.RootElement, sb, 0, false);
        return sb.ToString().TrimEnd();
    }

    private static void WriteYaml(JsonElement el, StringBuilder sb, int indent, bool inline)
    {
        string pad = new string(' ', indent * 2);
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                {
                    if (IsScalar(p.Value)) sb.AppendLine($"{pad}{p.Name}: {YamlScalar(p.Value)}");
                    else { sb.AppendLine($"{pad}{p.Name}:"); WriteYaml(p.Value, sb, indent + 1, false); }
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                {
                    if (IsScalar(item)) sb.AppendLine($"{pad}- {YamlScalar(item)}");
                    else { sb.AppendLine($"{pad}-"); WriteYaml(item, sb, indent + 1, false); }
                }
                break;
            default:
                sb.AppendLine($"{pad}{YamlScalar(el)}");
                break;
        }
    }

    private static bool IsScalar(JsonElement el) =>
        el.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array);

    private static string YamlScalar(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => "\"" + el.GetString()!.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"",
        JsonValueKind.Number => el.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "null",
        _ => el.GetRawText()
    };

    // ---------- JSON -> CSV ----------
    private static string JsonToCsv(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            throw new Exception("CSV export expects a JSON array of objects.");

        var rows = doc.RootElement.EnumerateArray().ToList();
        var headers = new List<string>();
        foreach (var row in rows)
            if (row.ValueKind == JsonValueKind.Object)
                foreach (var p in row.EnumerateObject())
                    if (!headers.Contains(p.Name)) headers.Add(p.Name);

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
        var rows = ParseCsv(csv);
        if (rows.Count < 1) return "[]";

        var headers = rows[0];
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

    private static string JsonEsc(string s)
        => System.Text.Json.JsonEncodedText.Encode(s).ToString();

    private static List<List<string>> ParseCsv(string csv)
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
                switch (ch)
                {
                    case '"': inQuotes = true; break;
                    case ',': row.Add(field.ToString()); field.Clear(); break;
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
            int indent = noComment.Length - noComment.TrimStart(' ').Length;
            lines.Add((indent, noComment.Trim()));
        }
        if (lines.Count == 0) return "{}";

        int pos = 0;
        var node = ParseYaml(lines, ref pos, lines[0].indent);
        var sb = new StringBuilder();
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
            if (inStr) { if (c == q) inStr = false; }
            else if (c == '"' || c == '\'') { inStr = true; q = c; }
            else if (c == '#' && (i == 0 || line[i - 1] == ' ')) return line[..i];
        }
        return line;
    }

    private static YNode ParseYaml(List<(int indent, string text)> lines, ref int pos, int indent)
    {
        if (lines[pos].text.StartsWith("- "))
        {
            var list = new YList();
            while (pos < lines.Count && lines[pos].indent == indent && lines[pos].text.StartsWith("- "))
            {
                string item = lines[pos].text[2..].Trim();
                if (item.Length == 0)
                {
                    pos++;
                    if (pos < lines.Count && lines[pos].indent > indent)
                        list.Items.Add(ParseYaml(lines, ref pos, lines[pos].indent));
                    else list.Items.Add(new YScalar(""));
                }
                else if (LooksLikeKey(item))
                {
                    // Inline map item: first entry on the dash line, more entries indented below.
                    var map = new YMap();
                    AddMapEntry(map, item);
                    pos++;
                    while (pos < lines.Count && lines[pos].indent > indent && !lines[pos].text.StartsWith("- "))
                    {
                        if (HandleMapLine(lines, ref pos, map)) continue;
                        break;
                    }
                    list.Items.Add(map);
                }
                else { pos++; list.Items.Add(new YScalar(item)); }
            }
            return list;
        }

        var topMap = new YMap();
        while (pos < lines.Count && lines[pos].indent == indent && !lines[pos].text.StartsWith("- "))
        {
            if (!HandleMapLine(lines, ref pos, topMap)) break;
        }
        return topMap;
    }

    private static bool HandleMapLine(List<(int indent, string text)> lines, ref int pos, YMap map)
    {
        var (ind, text) = lines[pos];
        int colon = FindColon(text);
        if (colon < 0) { pos++; return true; }

        string key = text[..colon].Trim().Trim('"', '\'');
        string val = text[(colon + 1)..].Trim();
        pos++;

        if (val.Length == 0)
        {
            if (pos < lines.Count && lines[pos].indent > ind)
                map.Items.Add((key, ParseYaml(lines, ref pos, lines[pos].indent)));
            else
                map.Items.Add((key, new YScalar("")));
        }
        else
        {
            map.Items.Add((key, new YScalar(val)));
        }
        return true;
    }

    private static void AddMapEntry(YMap map, string text)
    {
        int colon = FindColon(text);
        if (colon < 0) return;
        string key = text[..colon].Trim().Trim('"', '\'');
        string val = text[(colon + 1)..].Trim();
        map.Items.Add((key, new YScalar(val)));
    }

    private static bool LooksLikeKey(string text) => FindColon(text) >= 0;

    private static int FindColon(string text)
    {
        bool inStr = false; char q = '\0';
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (inStr) { if (c == q) inStr = false; }
            else if (c == '"' || c == '\'') { inStr = true; q = c; }
            else if (c == ':' && (i == text.Length - 1 || text[i + 1] == ' ')) return i;
        }
        return -1;
    }

    private abstract class YNode { public abstract void WriteJson(StringBuilder sb, int indent); }

    private sealed class YScalar : YNode
    {
        private readonly string _raw;
        public YScalar(string raw) => _raw = raw;

        public override void WriteJson(StringBuilder sb, int indent)
        {
            var v = _raw;
            if (v.Length == 0 || v == "null" || v == "~") { sb.Append("null"); return; }
            if (v == "true" || v == "false") { sb.Append(v); return; }
            if ((v.StartsWith('"') && v.EndsWith('"')) || (v.StartsWith('\'') && v.EndsWith('\'')))
            { sb.Append('"').Append(JsonEsc(v[1..^1])).Append('"'); return; }
            if (long.TryParse(v, out _) || double.TryParse(v, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out _))
            { sb.Append(v); return; }
            sb.Append('"').Append(JsonEsc(v)).Append('"');
        }
    }

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
            }
            sb.Append(new string(' ', indent * 2)).Append(']');
        }
    }
}
