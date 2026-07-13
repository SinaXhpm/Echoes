using System;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _jsonInput = string.Empty;
    [ObservableProperty] private string _jsonOutput = string.Empty;

    [RelayCommand]
    private void JsonAction(string mode)
    {
        try
        {
            ResetError();
            if (string.IsNullOrWhiteSpace(JsonInput)) return;

            var parseOptions = new JsonDocumentOptions { AllowTrailingCommas = true };
            JsonDocument jDoc;
            try
            {
                // If the input is already valid JSON, format/minify it verbatim. Running the lenient
                // key-quoting heuristic below on valid JSON would corrupt string values that contain
                // "word: " (log lines, URLs, times), so only fall back to it when strict parsing fails.
                jDoc = JsonDocument.Parse(JsonInput, parseOptions);
            }
            catch (JsonException)
            {
                // Lenient pass: quote bare object keys and turn 'single' into "double" quotes.
                string processed = Regex.Replace(JsonInput, @"(?<![""'])\b([a-zA-Z0-9_]+)\b(?=\s*:)", @"""$1""");
                processed = Regex.Replace(processed, @"'([^']*)'", @"""$1""");
                jDoc = JsonDocument.Parse(processed, parseOptions);
            }

            using (jDoc)
            {
                var writerOptions = new JsonWriterOptions { Indented = mode == "format" };
                using var stream = new System.IO.MemoryStream();
                using (var writer = new Utf8JsonWriter(stream, writerOptions))
                {
                    jDoc.WriteTo(writer);
                }
                JsonOutput = Encoding.UTF8.GetString(stream.ToArray());
            }
        }
        catch (Exception ex) { ErrorMessage = $"JSON Error: {ex.Message}"; }
    }
}