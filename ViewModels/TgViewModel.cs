using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public partial class TgViewModel : ObservableObject
{
    [ObservableProperty] private string _botToken = string.Empty;
    [ObservableProperty] private string _selectedMethod = "getMe";
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _customParameters = string.Empty;
    [ObservableProperty] private string _responseLog = string.Empty;
    [ObservableProperty] private bool _isBusy;

    private readonly Dictionary<string, string> _methodTemplates = new()
    {
        { "getMe", "" },
        { "getWebhookInfo", "" },
        { "deleteWebhook", "drop_pending_updates=true" },
        { "setWebhook", "url=\nmax_connections=40" },
        { "sendMessage", "chat_id=\ntext=Hello\nparse_mode=HTML" }
    };

    public List<string> AvailableMethods => new(_methodTemplates.Keys);

    public TgViewModel() => UpdateTemplate();

    partial void OnSelectedMethodChanged(string value) => UpdateTemplate();

    private void UpdateTemplate()
    {
        if (_methodTemplates.TryGetValue(SelectedMethod, out var template))
            CustomParameters = template;
    }

    [RelayCommand]
    private async Task ExecuteTg()
    {
        if (string.IsNullOrWhiteSpace(BotToken) || IsBusy) return;

        IsBusy = true;
        ResponseLog = "Executing cURL command...";

        try
        {
            var result = await Task.Run(() => RunCurl());

            if (string.IsNullOrWhiteSpace(result))
            {
                ResponseLog = "No response from cURL.";
                return;
            }

            try
            {
                using var doc = JsonDocument.Parse(result);
                var sb = new StringBuilder();
                ParseElement(doc.RootElement, sb, "");

                sb.AppendLine();
                sb.AppendLine("--------------------------------------------");
                sb.AppendLine("Response Received via Echoes");

                ResponseLog = sb.ToString();
            }
            catch
            {
                ResponseLog = result;
            }
        }
        catch (Exception ex)
        {
            ResponseLog = $"Error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private string RunCurl()
    {
        var url = $"https://api.telegram.org/bot{BotToken}/{SelectedMethod}";
        var args = new List<string> { "-s", "-X POST", "-L", "--connect-timeout 15" };

        if (!string.IsNullOrWhiteSpace(ProxyAddress))
        {
            args.Add($"-x \"{ProxyAddress}\"");
        }

        var lines = CustomParameters.Split('\n', System.StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var parts = line.Split('=', 2);
            if (parts.Length == 2)
                args.Add($"-d \"{parts[0].Trim()}={parts[1].Trim()}\"");
        }

        args.Add($"\"{url}\"");

        var psi = new ProcessStartInfo
        {
            FileName = "curl",
            Arguments = string.Join(" ", args),
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8
        };

        using var process = Process.Start(psi);
        return process?.StandardOutput.ReadToEnd() ?? string.Empty;
    }

    private void ParseElement(JsonElement element, StringBuilder sb, string indent)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Object)
                {
                    sb.AppendLine($"{indent}■ {property.Name.ToUpper()}:");
                    ParseElement(property.Value, sb, indent + "  ");
                }
                else if (property.Value.ValueKind == JsonValueKind.Array)
                {
                    sb.AppendLine($"{indent}■ {property.Name.ToUpper()}:");
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        ParseElement(item, sb, indent + "  - ");
                    }
                }
                else
                {
                    string key = property.Name.Replace("_", " ").PadRight(18);
                    sb.AppendLine($"{indent}  {key} : {property.Value}");
                }
            }
        }
        else
        {
            sb.AppendLine($"{indent}{element}");
        }
    }
}