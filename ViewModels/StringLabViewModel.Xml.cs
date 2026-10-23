using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _xmlInput = string.Empty;
    [ObservableProperty] private string _xmlOutput = string.Empty;

    [RelayCommand]
    private Task XmlAction(string mode)
    {
        string input = XmlInput;
        if (string.IsNullOrWhiteSpace(input)) { ResetError(); return Task.CompletedTask; }

        return RunOffUi("xml", () =>
        {
            try
            {
                return mode switch
                {
                    "minify" => RewriteXml(input, indent: false),
                    "json" => XmlToJson(input),
                    _ => RewriteXml(input, indent: true),
                };
            }
            catch (XmlException ex) when (ex.Message.Contains("DTD", StringComparison.OrdinalIgnoreCase))
            {
                throw new FormatException("DOCTYPE/DTD is not allowed (blocked to prevent XXE / entity-expansion attacks). Remove the <!DOCTYPE …> block.");
            }
            catch (XmlException ex)
            {
                throw new FormatException($"line {ex.LineNumber}, column {ex.LinePosition}: {ex.Message}");
            }
        }, r => XmlOutput = r, "XML: ");
    }

    // Hardened reader: no DTDs at all (so no external entities / billion-laughs), no resolver
    // (nothing is ever fetched from disk or network). Whitespace-only nodes are dropped so the
    // writer is free to re-indent; comments survive formatting but not minifying.
    private static XmlReader SafeXmlReader(string xml, bool keepComments) => XmlReader.Create(new StringReader(xml), new XmlReaderSettings
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        IgnoreWhitespace = true,
        IgnoreComments = !keepComments,
        IgnoreProcessingInstructions = false,
        MaxCharactersInDocument = 100_000_000,
    });

    private static string RewriteXml(string xml, bool indent)
    {
        using var reader = SafeXmlReader(xml, keepComments: indent);
        var sb = new StringBuilder(xml.Length);
        string? declaration = null;

        // Indentation grows with the depth on every line: 21 KB nested 3,000 deep formatted to 18 M chars (quadratic),
        // so the writer stops at the output ceiling.
        using (var writer = XmlWriter.Create(CappedText(sb, "Formatted XML"),new XmlWriterSettings
        {
            Indent = indent,
            IndentChars = "  ",
            NewLineChars = Environment.NewLine,
            // The writer would stamp its own encoding="utf-16" declaration on a StringWriter;
            // omit it and re-emit the document's original declaration verbatim instead.
            OmitXmlDeclaration = true,
            ConformanceLevel = ConformanceLevel.Document,
        }))
        {
            reader.Read();
            while (!reader.EOF)
            {
                if (reader.NodeType == XmlNodeType.XmlDeclaration)
                {
                    declaration = "<?xml " + reader.Value + "?>";
                    reader.Read();
                    continue;
                }
                writer.WriteNode(reader, defattr: false);   // copies the node + subtree and advances
            }
        }

        string body = sb.ToString();
        return declaration is null ? body : declaration + (indent ? Environment.NewLine : string.Empty) + body;
    }

    // Common convention: attributes → "@name", text → "#text" (or the plain value when an element
    // only holds text), repeated child names → arrays. Values stay strings — XML has no types.
    private static string XmlToJson(string xml)
    {
        XDocument doc;
        using (var reader = SafeXmlReader(xml, keepComments: false))
            doc = XDocument.Load(reader);
        if (doc.Root is null) throw new FormatException("No root element.");

        var root = doc.Root;
        return WriteJsonCapped(IndentedJson, w =>
        {
            w.WriteStartObject();
            w.WritePropertyName(root.Name.LocalName);
            WriteXElement(root, w, 0);
            w.WriteEndObject();
        }, "JSON output");
    }

    private static void WriteXElement(XElement el, Utf8JsonWriter w, int depth)
    {
        // Utf8JsonWriter refuses > 1000 levels anyway; stop earlier with a readable message.
        if (depth > 256) throw new FormatException("XML nesting is too deep to convert.");

        var attrs = el.Attributes().Where(a => !a.IsNamespaceDeclaration).ToList();
        var children = el.Elements().ToList();
        string text = string.Concat(el.Nodes().OfType<XText>().Select(t => t.Value)).Trim();

        if (attrs.Count == 0 && children.Count == 0)
        {
            if (text.Length == 0 && el.IsEmpty) w.WriteNullValue();
            else w.WriteStringValue(text);
            return;
        }

        w.WriteStartObject();
        foreach (var a in attrs) w.WriteString("@" + a.Name.LocalName, a.Value);
        foreach (var group in children.GroupBy(c => c.Name.LocalName))
        {
            w.WritePropertyName(group.Key);
            var items = group.ToList();
            if (items.Count == 1) WriteXElement(items[0], w, depth + 1);
            else
            {
                w.WriteStartArray();
                foreach (var item in items) WriteXElement(item, w, depth + 1);
                w.WriteEndArray();
            }
        }
        if (text.Length > 0) w.WriteString("#text", text);
        w.WriteEndObject();
    }
}
