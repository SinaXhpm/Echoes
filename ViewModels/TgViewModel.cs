using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
        ResponseLog = "Executing...";

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            psi.ArgumentList.Add("-s");
            psi.ArgumentList.Add("-v");
            psi.ArgumentList.Add("-L");
            psi.ArgumentList.Add("-k");
            psi.ArgumentList.Add("--connect-timeout");
            psi.ArgumentList.Add("15");

            if (!string.IsNullOrWhiteSpace(ProxyAddress))
            {
                var proxy = ProxyAddress.Trim();
                if (!proxy.Contains("://"))
                {
                    if (proxy.Contains(":1080") || proxy.Contains(":1081") || proxy.Contains(":9050"))
                        proxy = "socks5://" + proxy;
                    else
                        proxy = "http://" + proxy;
                }
                psi.ArgumentList.Add("-x");
                psi.ArgumentList.Add(proxy);
            }

            var lines = CustomParameters.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                {
                    psi.ArgumentList.Add("-d");
                    psi.ArgumentList.Add($"{parts[0].Trim()}={parts[1].Trim()}");
                }
            }

            psi.ArgumentList.Add($"https://api.telegram.org/bot{BotToken}/{SelectedMethod}");

            using var process = new Process { StartInfo = psi };
            process.Start();

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();

            await Task.WhenAll(outputTask, errorTask);
            await process.WaitForExitAsync();

            string result = outputTask.Result;
            string verboseLog = errorTask.Result;

            var sb = new StringBuilder();

            if (!string.IsNullOrWhiteSpace(result))
            {
                try
                {
                    using var doc = JsonDocument.Parse(result);
                    ParseElement(doc.RootElement, sb, "");
                }
                catch
                {
                    sb.AppendLine(result);
                }
            }

            //if (!string.IsNullOrWhiteSpace(verboseLog))
            //{
            //    sb.AppendLine();
            //    sb.AppendLine("--- CONNECTION INFO ---");
            //    var logs = verboseLog.Split('\n');
            //    foreach (var log in logs)
            //    {
            //        if (log.StartsWith("*") || log.Contains("HTTP/"))
            //            sb.AppendLine(log);
            //    }
            //}

            ResponseLog = sb.Length > 0 ? sb.ToString() : "Empty response.";
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