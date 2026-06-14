using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsClient;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public partial class DnsViewModel : ObservableObject
{
    [ObservableProperty] private string _domainName = string.Empty;
    [ObservableProperty] private string _logText = string.Empty;
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private string _dnsServersText = string.Empty;

    [ObservableProperty] private bool _typeA = true;
    [ObservableProperty] private bool _typeAAAA;
    [ObservableProperty] private bool _typeMX;
    [ObservableProperty] private bool _typeNS;
    [ObservableProperty] private bool _typeTXT;
    [ObservableProperty] private bool _typeCNAME;
    [ObservableProperty] private bool _typeSOA;
    [ObservableProperty] private bool _typeSRV;
    [ObservableProperty] private bool _typeCAA;
    [ObservableProperty] private bool _typePTR;

    public ObservableCollection<string> DomainHistory => HistoryService.Instance.Get("dns.domain");

    public DnsViewModel()
    {
        LoadServers();
        if (HistoryService.Instance.Last("dns.domain") is { } last) DomainName = last;
    }

    private void LoadServers()
    {
        DnsServersText = ProfileService.Instance.GetSetting("dns.servers") ?? string.Empty;

        if (string.IsNullOrWhiteSpace(DnsServersText))
        {
            DnsServersText = "1.1.1.1" + Environment.NewLine + "8.8.8.8";
            SaveServers();
        }
    }

    private void SaveServers()
        => ProfileService.Instance.SetSetting("dns.servers", DnsServersText);

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task RunLookup()
    {
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;
        HistoryService.Instance.Add("dns.domain", DomainName);
        SaveServers();
        IsWorking = true;
        _logBuilder.Clear();
        LogText = string.Empty;

        var servers = DnsServersText.Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim()).Where(s => IPAddress.TryParse(s, out _)).ToList();

        var selectedTypes = GetSelectedTypes();
        if (!selectedTypes.Any() || !servers.Any())
        {
            IsWorking = false;
            return;
        }

        var tasks = servers.Select(async server =>
        {
            foreach (var type in selectedTypes)
            {
                try
                {
                    var options = new LookupClientOptions(IPAddress.Parse(server)) { Timeout = TimeSpan.FromSeconds(3), Retries = 0 };
                    var client = new LookupClient(options);

                    // PTR on an IP → reverse lookup; everything else is a forward query.
                    var result = (type == QueryType.PTR && IPAddress.TryParse(DomainName.Trim(), out var revIp))
                        ? await client.QueryReverseAsync(revIp)
                        : await client.QueryAsync(DomainName, type);

                    var sb = new StringBuilder();
                    if (result.Answers.Any())
                    {
                        foreach (var record in result.Answers)
                            sb.AppendLine($"{server,-15} | {type,-5} | {record}");
                    }
                    else
                    {
                        sb.AppendLine($"{server,-15} | {type,-5} | no records");
                    }
                    UpdateLog(sb.ToString());
                }
                catch
                {
                    UpdateLog($"{server,-15} | {type,-5} | timeout");
                }
            }
        });

        await Task.WhenAll(tasks);
        IsWorking = false;
    }

    [RelayCommand]
    private async Task RunWhois()
    {
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;
        HistoryService.Instance.Add("dns.domain", DomainName);
        IsWorking = true;
        string query = DomainName.Trim();
        LogText = $"# whois {query}" + Environment.NewLine;

        // rdap.org is the IANA bootstrap — it follows to the authoritative RDAP server for any
        // TLD/registry, and also covers IPs and ASNs. Pick the right object type from the input.
        string kind =
            System.Net.IPAddress.TryParse(query, out _) ? "ip" :
            System.Text.RegularExpressions.Regex.IsMatch(query, @"^(AS)?\d+$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
                ? "autnum" : "domain";
        string key = kind == "autnum" ? query.TrimStart('A', 'S', 'a', 's') : query;

        var providers = new List<string> { $"https://rdap.org/{kind}/{key}" };
        if (kind == "domain")
            providers.Add($"https://rdap.verisign.com/com/v1/domain/{key}");   // .com/.net fallback

        foreach (var url in providers)
        {
            try
            {
                var result = await FetchRdap(url);
                if (!string.IsNullOrWhiteSpace(result) && result.Contains("{"))
                {
                    using var doc = JsonDocument.Parse(result);
                    var sb = new StringBuilder();
                    ParseElement(doc.RootElement, sb);
                    LogText = TextLimit.Cap(sb.ToString());
                    IsWorking = false;
                    return;
                }
            }
            catch { }
        }
        LogText = "timeout / failed";
        IsWorking = false;
    }

    private static async Task<string> FetchRdap(string url)
    {
        using var client = HttpHelper.Create(timeout: TimeSpan.FromSeconds(10));
        client.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");

        using var response = await client.GetAsync(url);
        return await response.Content.ReadAsStringAsync();
    }

    private void ParseElement(JsonElement element, StringBuilder sb)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Object || property.Value.ValueKind == JsonValueKind.Array)
                    ParseElement(property.Value, sb);
                else
                    sb.AppendLine($"{property.Name}: {property.Value}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray()) ParseElement(item, sb);
        }
    }

    private List<QueryType> GetSelectedTypes()
    {
        var types = new List<QueryType>();
        if (TypeA) types.Add(QueryType.A);
        if (TypeAAAA) types.Add(QueryType.AAAA);
        if (TypeMX) types.Add(QueryType.MX);
        if (TypeNS) types.Add(QueryType.NS);
        if (TypeTXT) types.Add(QueryType.TXT);
        if (TypeCNAME) types.Add(QueryType.CNAME);
        if (TypeSOA) types.Add(QueryType.SOA);
        if (TypeSRV) types.Add(QueryType.SRV);
        if (TypeCAA) types.Add(QueryType.CAA);
        if (TypePTR) types.Add(QueryType.PTR);
        return types;
    }

    [RelayCommand]
    private async Task CopyResult()
    {
        if (string.IsNullOrWhiteSpace(LogText)) return;
        await ClipboardHelper.SetTextAsync(LogText);
    }

    private readonly StringBuilder _logBuilder = new();

    private void UpdateLog(string msg)
    {
        Dispatcher.UIThread.Post(() =>
        {
            _logBuilder.Append(msg);
            LogText = TextLimit.Cap(_logBuilder.ToString());
        });
    }
}