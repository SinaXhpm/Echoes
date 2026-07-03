using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net.Http;
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

    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("tg.proxy");

    private bool _loaded;
    // NOTE: BotToken is intentionally NOT persisted (sensitive).
    private static readonly HashSet<string> PersistProps = new()
    { "SelectedMethod", "ProxyAddress", "CustomParameters" };

    public TgViewModel()
    {
        var ps = ProfileService.Instance;
        ps.Remove("tg.token");   // purge any token saved by an earlier build
        SelectedMethod = ps.GetSetting("tg.method") ?? "getMe";
        var savedParams = ps.GetSetting("tg.params");
        if (!string.IsNullOrEmpty(savedParams)) CustomParameters = savedParams; else UpdateTemplate();
        ProxyAddress = ps.GetSetting("tg.proxy") ?? (HistoryService.Instance.Last("tg.proxy") ?? string.Empty);
        _loaded = true;
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n))
            ProfileService.Instance.SetMany(
                ("tg.method", SelectedMethod),
                ("tg.params", CustomParameters), ("tg.proxy", ProxyAddress));
    }

    partial void OnSelectedMethodChanged(string value) => UpdateTemplate();

    private void UpdateTemplate()
    {
        if (_methodTemplates.TryGetValue(SelectedMethod, out var template))
            CustomParameters = template;
    }

    [RelayCommand]
    private async Task CopyResponse()
    {
        if (!string.IsNullOrWhiteSpace(ResponseLog))
            await ClipboardHelper.SetTextAsync(ResponseLog);
    }

    [RelayCommand]
    private void ClearResponse() => ResponseLog = string.Empty;

    [RelayCommand]
    private async Task ExecuteTg()
    {
        if (string.IsNullOrWhiteSpace(BotToken) || IsBusy) return;

        IsBusy = true;
        ResponseLog = "Executing...";

        if (!string.IsNullOrWhiteSpace(ProxyAddress)) HistoryService.Instance.Add("tg.proxy", ProxyAddress);

        try
        {
            string? proxy = string.IsNullOrWhiteSpace(ProxyAddress) ? null : ProxyAddress;
            // Verify TLS — the bot token is a credential and must not be sent over an unverified connection.
            using var client = HttpHelper.Create(proxy, timeout: TimeSpan.FromSeconds(15));

            var fields = new List<KeyValuePair<string, string>>();
            var lines = CustomParameters.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                    fields.Add(new KeyValuePair<string, string>(parts[0].Trim(), parts[1].Trim()));
            }

            using var content = new FormUrlEncodedContent(fields);
            var url = $"https://api.telegram.org/bot{BotToken}/{SelectedMethod}";

            using var response = await client.PostAsync(url, content);
            string result = await response.Content.ReadAsStringAsync();

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

            ResponseLog = sb.Length > 0 ? TextLimit.Cap(sb.ToString()) : "Empty response.";
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