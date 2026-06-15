using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public partial class IpInfoViewModel : ObservableObject
{
    [ObservableProperty] private string _targetIp = string.Empty;
    [ObservableProperty] private string _rawResult = string.Empty;
    [ObservableProperty] private bool _isWorking;

    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;

    // HTTPS sources first; ip-api.com (HTTP only on the free tier) is the last-resort fallback.
    private readonly string[] _selfEndpoints =
    {
        "https://ipwho.is/",
        "https://ipapi.co/json/",
        "https://get.geojs.io/v1/ip/geo.json",
        "https://freeipapi.com/api/json/",
        "http://ip-api.com/json/?fields=66846719"
    };

    private readonly string[] _lookupEndpoints =
    {
        "https://ipwho.is/{0}",
        "https://ipapi.co/{0}/json/",
        "https://get.geojs.io/v1/ip/geo/{0}.json",
        "https://freeipapi.com/api/json/{0}",
        "http://ip-api.com/json/{0}?fields=66846719"
    };

    public ObservableCollection<string> TargetHistory => HistoryService.Instance.Get("ip.target");
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("ip.proxy");

    [ObservableProperty] private string _subnetInput = "192.168.1.0/24";
    [ObservableProperty] private string _subnetOutput = string.Empty;

    private bool _loaded;
    private static readonly System.Collections.Generic.HashSet<string> PersistProps = new()
    { "UseProxy", "ProxyAddress", "ProxyUser", "ProxyPass" };

    public IpInfoViewModel()
    {
        var ps = ProfileService.Instance;
        UseProxy = ps.GetBool("ip.useProxy");
        ProxyAddress = ps.GetSetting("ip.proxyAddr") ?? (HistoryService.Instance.Last("ip.proxy") ?? string.Empty);
        ProxyUser = ps.GetSetting("ip.proxyUser") ?? string.Empty;
        ProxyPass = ps.GetSetting("ip.proxyPass") ?? string.Empty;
        _loaded = true;
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n))
            ProfileService.Instance.SetMany(
                ("ip.useProxy", UseProxy ? "true" : "false"), ("ip.proxyAddr", ProxyAddress),
                ("ip.proxyUser", ProxyUser), ("ip.proxyPass", ProxyPass));
    }

    [RelayCommand]
    private void RunSubnet()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(SubnetInput)) return;
            SubnetOutput = SubnetCalc.Describe(SubnetInput);
        }
        catch (Exception ex) { SubnetOutput = "Error: " + ex.Message; }
    }

    [RelayCommand]
    private async Task CopyResult() => await ClipboardHelper.SetTextAsync(RawResult);

    [RelayCommand]
    private async Task CopySubnet() => await ClipboardHelper.SetTextAsync(SubnetOutput);

    [RelayCommand]
    private async Task GetMyIp()
    {
        TargetIp = string.Empty;
        await FetchIpInfo(string.Empty);
    }

    [RelayCommand]
    private async Task LookupIp()
    {
        HistoryService.Instance.Add("ip.target", TargetIp);
        await FetchIpInfo(TargetIp);
    }

    private async Task FetchIpInfo(string ip)
    {
        IsWorking = true;
        RawResult = "Fetching information...";
        var errorLog = new StringBuilder();

        string? proxy = UseProxy && !string.IsNullOrWhiteSpace(ProxyAddress) ? ProxyAddress : null;
        if (proxy != null) HistoryService.Instance.Add("ip.proxy", proxy);
        using var client = HttpHelper.Create(proxy, ProxyUser, ProxyPass, timeout: TimeSpan.FromSeconds(8));

        bool self = string.IsNullOrWhiteSpace(ip);
        var endpoints = self ? _selfEndpoints : _lookupEndpoints;

        foreach (var endpoint in endpoints)
        {
            try
            {
                string url = self ? endpoint : string.Format(endpoint, ip);
                string response = await client.GetStringAsync(url);

                if (!string.IsNullOrWhiteSpace(response))
                {
                    int firstBrace = response.IndexOf('{');
                    int lastBrace = response.LastIndexOf('}');

                    if (firstBrace != -1 && lastBrace != -1)
                    {
                        string jsonOnly = response.Substring(firstBrace, (lastBrace - firstBrace) + 1);
                        try
                        {
                            using var doc = JsonDocument.Parse(jsonOnly);
                            var sb = new StringBuilder();
                            ParseElement(doc.RootElement, sb, "");

                            sb.AppendLine();
                            sb.AppendLine("--------------------------------------------");
                            sb.AppendLine("Generated by Echoes");

                            RawResult = TextLimit.Cap(sb.ToString());
                            IsWorking = false;
                            return;
                        }
                        catch
                        {
                            RawResult = TextLimit.Cap(response.Trim()) + Environment.NewLine + Environment.NewLine + "Echoes";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                errorLog.AppendLine($"Error: {ex.Message}");
            }
        }
        RawResult = "Failed." + Environment.NewLine + errorLog.ToString() + Environment.NewLine + "Echoes";
        IsWorking = false;
    }

    private void ParseElement(JsonElement element, StringBuilder sb, string indent)
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
                sb.AppendLine($"{indent}■ {property.Name.ToUpper()}: {property.Value.GetRawText()}");
            }
            else
            {
                string key = property.Name.Replace("_", " ").PadRight(15);
                sb.AppendLine($"{indent}  {key} : {property.Value}");
            }
        }
    }
}