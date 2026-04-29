using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DnsClient;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace Echoes.ViewModels;

public partial class DnsViewModel : ObservableObject
{
    [ObservableProperty] private string _domainName = string.Empty;
    [ObservableProperty] private string _logText = string.Empty;
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private string _newDnsServer = string.Empty;

    [ObservableProperty] private bool _typeA = true;
    [ObservableProperty] private bool _typeAAAA;
    [ObservableProperty] private bool _typeMX;
    [ObservableProperty] private bool _typeNS;
    [ObservableProperty] private bool _typeTXT;
    [ObservableProperty] private bool _typeCNAME;

    public ObservableCollection<string> DnsServers { get; } = new();

    private readonly string _storagePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dns_settings.txt");

    public DnsViewModel()
    {
        LoadServers();
    }

    private void LoadServers()
    {
        try
        {
            if (File.Exists(_storagePath))
            {
                var lines = File.ReadAllLines(_storagePath);
                foreach (var line in lines)
                {
                    if (!string.IsNullOrWhiteSpace(line)) DnsServers.Add(line.Trim());
                }
            }
        }
        catch { }

        if (DnsServers.Count == 0)
        {
            DnsServers.Add("1.1.1.1");
            DnsServers.Add("8.8.8.8");
            SaveServers();
        }
    }

    private void SaveServers()
    {
        try
        {
            File.WriteAllLines(_storagePath, DnsServers);
        }
        catch { }
    }

    [RelayCommand]
    private void AddDnsServer()
    {
        if (!string.IsNullOrWhiteSpace(NewDnsServer) && IPAddress.TryParse(NewDnsServer, out _))
        {
            if (!DnsServers.Contains(NewDnsServer))
            {
                DnsServers.Add(NewDnsServer);
                SaveServers();
            }
            NewDnsServer = string.Empty;
        }
    }

    [RelayCommand]
    private void RemoveDnsServer(string server)
    {
        DnsServers.Remove(server);
        if (DnsServers.Count == 0) DnsServers.Add("1.1.1.1");
        SaveServers();
    }

    [RelayCommand]
    private async Task RunLookup()
    {
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;
        IsWorking = true;
        LogText = string.Empty;

        var selectedTypes = GetSelectedTypes();
        if (!selectedTypes.Any()) { UpdateLog("Select at least one record type."); IsWorking = false; return; }

        var queryTasks = DnsServers
            .Where(server => IPAddress.TryParse(server, out _))
            .SelectMany(server => selectedTypes.Select(async type =>
            {
                try
                {
                    var options = new LookupClientOptions(IPAddress.Parse(server))
                    {
                        Timeout = TimeSpan.FromSeconds(5),
                        Retries = 0
                    };
                    var client = new LookupClient(options);
                    var result = await client.QueryAsync(DomainName, type);

                    var sb = new StringBuilder();
                    sb.AppendLine($"--- [{type}] via {server} ---");
                    foreach (var record in result.Answers) sb.AppendLine(record.ToString());
                    if (!result.Answers.Any()) sb.AppendLine("(no records)");
                    sb.AppendLine();

                    UpdateLog(sb.ToString());
                }
                catch (Exception ex)
                {
                    UpdateLog($"Error [{type}] via {server}: {ex.Message}{Environment.NewLine}");
                }
            }));

        await Task.WhenAll(queryTasks);
        IsWorking = false;
    }

    [RelayCommand]
    private async Task RunWhois()
    {
        if (string.IsNullOrWhiteSpace(DomainName) || IsWorking) return;
        IsWorking = true;
        LogText = string.Empty;

        string[] providers = {
            $"https://rdap.org/domain/{DomainName}",
            $"https://rdap.verisign.com/com/v1/domain/{DomainName}",
            $"https://rdap.apnic.net/domain/{DomainName}"
        };

        bool success = false;

        foreach (var url in providers)
        {
            try
            {
                var result = await Task.Run(() => RunCurl(url));
                if (!string.IsNullOrWhiteSpace(result) && result.Contains("{"))
                {
                    using var doc = JsonDocument.Parse(result);
                    var sb = new StringBuilder();
                    ParseElement(doc.RootElement, sb, "");

                    sb.AppendLine();
                    sb.AppendLine("--------------------------------------------");
                    sb.AppendLine("RDAP Lookup Successful");

                    LogText = sb.ToString();
                    success = true;
                    break;
                }
            }
            catch { }
        }

        if (!success) LogText = "WHOIS/RDAP lookup failed on all providers.";
        IsWorking = false;
    }

    private string RunCurl(string url)
    {
        var args = new List<string> { "-s", "-L", "--connect-timeout 10" };
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
                    string key = property.Name.Replace("_", " ").PadRight(20);
                    sb.AppendLine($"{indent}  {key} : {property.Value}");
                }
            }
        }
        else
        {
            sb.AppendLine($"{indent}{element}");
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

    private void UpdateLog(string m)
    {
        Dispatcher.UIThread.Post(() => LogText += $"{m}{Environment.NewLine}");
    }
}