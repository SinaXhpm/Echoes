using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsClient;
using System;
using System.Collections.Generic;
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

    private readonly string _storagePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dns_settings.txt");

    public DnsViewModel()
    {
        LoadServers();
    }

    private void LoadServers()
    {
        try
        {
            if (File.Exists(_storagePath)) DnsServersText = File.ReadAllText(_storagePath);
        }
        catch { }

        if (string.IsNullOrWhiteSpace(DnsServersText))
        {
            DnsServersText = "1.1.1.1" + Environment.NewLine + "8.8.8.8";
            SaveServers();
        }
    }

    private void SaveServers()
    {
        try { File.WriteAllText(_storagePath, DnsServersText); } catch { }
    }

    [RelayCommand(AllowConcurrentExecutions = true)]
    private async Task RunLookup()
    {
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;
        SaveServers();
        IsWorking = true;
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
                    var result = await client.QueryAsync(DomainName, type);

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
        IsWorking = true;
        LogText = $"# whois {DomainName}" + Environment.NewLine;

        string[] providers = {
            $"https://rdap.org/domain/{DomainName}",
            $"https://rdap.verisign.com/com/v1/domain/{DomainName}"
        };

        foreach (var url in providers)
        {
            try
            {
                var result = await Task.Run(() => RunCurl(url));
                if (!string.IsNullOrWhiteSpace(result) && result.Contains("{"))
                {
                    using var doc = JsonDocument.Parse(result);
                    var sb = new StringBuilder();
                    ParseElement(doc.RootElement, sb);
                    LogText = sb.ToString();
                    IsWorking = false;
                    return;
                }
            }
            catch { }
        }
        LogText = "timeout / failed";
        IsWorking = false;
    }

    private string RunCurl(string url)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "curl",
            Arguments = $"-s -L --connect-timeout 5 \"{url}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8
        };
        using var process = Process.Start(psi);
        return process?.StandardOutput.ReadToEnd() ?? string.Empty;
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
        return types;
    }

    private void UpdateLog(string msg)
    {
        Dispatcher.UIThread.Post(() => LogText += msg);
    }
}