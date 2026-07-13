using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>One worldwide check-host.net probe node and its live result.</summary>
public sealed partial class CheckHostNodeRow : ObservableObject
{
    public required string CountryCode { get; init; }
    public required string Country { get; init; }
    public required string City { get; init; }
    public required string NodeHost { get; init; }
    public string Location => string.Join(", ", new[] { Country, City }.Where(s => s.Length > 0));
    public bool HasFlag => CountryCode.Trim().Length == 2;

    [ObservableProperty] private string _resultText = "…";
    [ObservableProperty] private int _state;   // 0 = pending, 1 = ok, 2 = fail

    public bool IsPending => State == 0;
    public bool IsOk => State == 1;
    public bool IsFail => State == 2;
    partial void OnStateChanged(int value)
    {
        OnPropertyChanged(nameof(IsPending));
        OnPropertyChanged(nameof(IsOk));
        OnPropertyChanged(nameof(IsFail));
    }
}

/// <summary>
/// Runs distributed reachability checks (ping / HTTP / TCP / DNS) from check-host.net's global nodes
/// and shows each node's result. All calls go through the app's <see cref="HttpHelper"/>, so an optional
/// proxy can tunnel the API requests (handy where check-host.net itself is filtered). Pure managed BCL.
/// </summary>
public partial class CheckHostViewModel : ObservableObject
{
    private static readonly string[] Types = { "ping", "http", "tcp", "dns" };

    [ObservableProperty] private string _host = string.Empty;
    [ObservableProperty] private int _selectedTypeIndex;          // 0 ping · 1 http · 2 tcp · 3 dns
    [ObservableProperty] private int _maxNodes = 20;
    [ObservableProperty] private bool _isWorking;
    [ObservableProperty] private string _statusMessage = "Enter a host and RUN to probe from worldwide nodes.";

    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;

    public ObservableCollection<string> CheckTypes { get; } = new() { "Ping", "HTTP", "TCP", "DNS" };
    public ObservableCollection<CheckHostNodeRow> Nodes { get; } = new();

    public ObservableCollection<string> HostHistory => HistoryService.Instance.Get("checkhost.host");
    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("ip.proxy");

    public int OkCount => Nodes.Count(n => n.IsOk);
    public int TotalCount => Nodes.Count;

    private CancellationTokenSource? _cts;
    private bool _loaded;
    private static readonly HashSet<string> PersistProps = new()
    { "UseProxy", "ProxyAddress", "ProxyUser", "ProxyPass", "SelectedTypeIndex", "MaxNodes" };

    public CheckHostViewModel()
    {
        var ps = ProfileService.Instance;
        UseProxy = ps.GetBool("checkhost.useProxy");
        ProxyAddress = ps.GetSetting("checkhost.proxyAddr") ?? (HistoryService.Instance.Last("ip.proxy") ?? string.Empty);
        ProxyUser = ps.GetSetting("checkhost.proxyUser") ?? string.Empty;
        ProxyPass = ps.GetSetting("checkhost.proxyPass") ?? string.Empty;
        if (int.TryParse(ps.GetSetting("checkhost.type"), out int ti) && ti is >= 0 and <= 3) SelectedTypeIndex = ti;
        if (int.TryParse(ps.GetSetting("checkhost.maxNodes"), out int mn) && mn is > 0 and <= 100) MaxNodes = mn;
        _loaded = true;
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n))
            ProfileService.Instance.SetMany(
                ("checkhost.useProxy", UseProxy ? "true" : "false"), ("checkhost.proxyAddr", ProxyAddress),
                ("checkhost.proxyUser", ProxyUser), ("checkhost.proxyPass", ProxyPass),
                ("checkhost.type", SelectedTypeIndex.ToString()), ("checkhost.maxNodes", MaxNodes.ToString()));
    }

    // Synchronous command → it stays enabled while a run is in flight, so STOP is always clickable.
    // (An async [RelayCommand] disables itself for the duration of the task, which blocked STOP.)
    [RelayCommand]
    private void ToggleRun()
    {
        if (IsWorking) { _cts?.Cancel(); return; }
        _ = RunCheck();
    }

    private async Task RunCheck()
    {
        string host = Host.Trim();
        if (host.Length == 0) { StatusMessage = "Enter a host or IP to check."; return; }

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        Nodes.Clear();
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(OkCount));
        IsWorking = true;
        string type = Types[Math.Clamp(SelectedTypeIndex, 0, 3)];

        try
        {
            HistoryService.Instance.Add("checkhost.host", host);
            string? proxy = UseProxy && !string.IsNullOrWhiteSpace(ProxyAddress) ? ProxyAddress : null;
            if (proxy != null) HistoryService.Instance.Add("ip.proxy", proxy);

            using var client = HttpHelper.Create(proxy, ProxyUser, ProxyPass, timeout: TimeSpan.FromSeconds(15));
            client.DefaultRequestHeaders.Accept.ParseAdd("application/json");

            string url = $"https://check-host.net/check-{type}?host={Uri.EscapeDataString(host)}";
            if (MaxNodes > 0) url += $"&max_nodes={MaxNodes}";

            StatusMessage = "Requesting nodes…";
            string json = await client.GetStringAsync(url, token);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (!(root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.Number && okEl.GetInt32() == 1))
            {
                StatusMessage = root.TryGetProperty("error", out var er)
                    ? "check-host.net: " + er.GetString()
                    : "check-host.net rejected the request (bad host or rate-limited).";
                IsWorking = false;
                return;
            }

            string requestId = root.TryGetProperty("request_id", out var ridEl) ? ridEl.GetString() ?? "" : "";
            var rowByNode = new Dictionary<string, CheckHostNodeRow>(StringComparer.Ordinal);

            if (root.TryGetProperty("nodes", out var nodesEl) && nodesEl.ValueKind == JsonValueKind.Object)
            {
                foreach (var np in nodesEl.EnumerateObject())
                {
                    // Current format: ["cc", "Country", "City", "ip", "AS…"].
                    string cc = "", country = "", city = "";
                    if (np.Value.ValueKind == JsonValueKind.Array)
                    {
                        var a = np.Value;
                        if (a.GetArrayLength() > 0 && a[0].ValueKind == JsonValueKind.String) cc = a[0].GetString() ?? "";
                        if (a.GetArrayLength() > 1 && a[1].ValueKind == JsonValueKind.String) country = a[1].GetString() ?? "";
                        if (a.GetArrayLength() > 2 && a[2].ValueKind == JsonValueKind.String) city = a[2].GetString() ?? "";
                    }
                    // Fallback for the older shape ["cc", "Country, City", "ip"].
                    if (country.Contains(','))
                    {
                        int c = country.IndexOf(',');
                        city = country[(c + 1)..].Trim();
                        country = country[..c].Trim();
                    }

                    var row = new CheckHostNodeRow
                    {
                        CountryCode = cc,
                        Country = country,
                        City = city,
                        NodeHost = np.Name,
                    };
                    Nodes.Add(row);
                    rowByNode[np.Name] = row;
                }
            }

            OnPropertyChanged(nameof(TotalCount));
            if (rowByNode.Count == 0 || string.IsNullOrEmpty(requestId))
            {
                StatusMessage = "No nodes were assigned. Try again in a moment.";
                IsWorking = false;
                return;
            }

            StatusMessage = $"{rowByNode.Count} nodes · collecting results…";
            string resultUrl = "https://check-host.net/check-result/" + requestId;

            for (int i = 0; i < 12 && !token.IsCancellationRequested; i++)
            {
                await Task.Delay(1200, token);
                string rjson;
                try { rjson = await client.GetStringAsync(resultUrl, token); }
                catch (OperationCanceledException) { throw; }
                catch { continue; }

                bool allDone = ApplyResults(rjson, rowByNode, type);
                OnPropertyChanged(nameof(OkCount));
                if (allDone) break;
            }

            // Anything still pending after the polling window → mark as no-response.
            foreach (var row in Nodes)
                if (row.IsPending) { row.ResultText = "no response"; row.State = 2; }

            OnPropertyChanged(nameof(OkCount));
            StatusMessage = $"Done · {OkCount}/{TotalCount} nodes reachable";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Stopped.";
        }
        catch (Exception ex)
        {
            StatusMessage = "Error: " + ex.Message;
        }
        finally
        {
            IsWorking = false;
        }
    }

    // Fold a /check-result payload into the node rows. Returns true when every node has a final result.
    private static bool ApplyResults(string json, Dictionary<string, CheckHostNodeRow> rows, string type)
    {
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch { return false; }
        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;

            bool allDone = true;
            foreach (var (name, row) in rows)
            {
                if (!row.IsPending) continue;
                if (!root.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) { allDone = false; continue; }
                if (v.ValueKind != JsonValueKind.Array || v.GetArrayLength() == 0) { allDone = false; continue; }

                var payload = v[0];
                if (payload.ValueKind == JsonValueKind.Null) { allDone = false; continue; }

                var (text, state) = Format(type, payload);
                row.ResultText = text;
                row.State = state;
            }
            return allDone;
        }
    }

    private static (string text, int state) Format(string type, JsonElement p)
    {
        try
        {
            switch (type)
            {
                case "ping":
                {
                    if (p.ValueKind != JsonValueKind.Array) return ("no data", 2);
                    int total = 0, ok = 0; double sum = 0;
                    foreach (var att in p.EnumerateArray())
                    {
                        total++;
                        if (att.ValueKind == JsonValueKind.Array && att.GetArrayLength() >= 1
                            && att[0].ValueKind == JsonValueKind.String && att[0].GetString() == "OK")
                        {
                            ok++;
                            if (att.GetArrayLength() >= 2 && att[1].TryGetDouble(out double t)) sum += t;
                        }
                    }
                    if (ok == 0) return ($"0/{total} · timeout", 2);
                    return ($"{ok}/{total} · {Ms(sum / ok)} avg", 1);
                }
                case "http":
                {
                    if (p.ValueKind != JsonValueKind.Array || p.GetArrayLength() == 0) return ("no data", 2);
                    bool success = p[0].ValueKind == JsonValueKind.Number ? p[0].GetInt32() == 1
                                 : p[0].ValueKind == JsonValueKind.True;
                    double time = p.GetArrayLength() > 1 && p[1].TryGetDouble(out double tt) ? tt : 0;
                    string statusText = p.GetArrayLength() > 2 && p[2].ValueKind == JsonValueKind.String ? p[2].GetString() ?? "" : "";
                    string code = p.GetArrayLength() > 3 && p[3].ValueKind == JsonValueKind.String ? p[3].GetString() ?? "" : "";
                    if (success)
                    {
                        string head = code.Length > 0 ? code : "OK";
                        return (time > 0 ? $"{head} · {Ms(time)}" : head, 1);
                    }
                    return (statusText.Length > 0 ? statusText : (code.Length > 0 ? code : "failed"), 2);
                }
                case "tcp":
                {
                    if (p.ValueKind != JsonValueKind.Object) return ("no data", 2);
                    if (p.TryGetProperty("error", out var er))
                        return ("error: " + (er.GetString() ?? "failed"), 2);
                    if (p.TryGetProperty("time", out var tm) && tm.TryGetDouble(out double t))
                    {
                        string addr = p.TryGetProperty("address", out var ad) && ad.ValueKind == JsonValueKind.String ? ad.GetString() ?? "" : "";
                        return (addr.Length > 0 ? $"open · {Ms(t)} · {addr}" : $"open · {Ms(t)}", 1);
                    }
                    return ("failed", 2);
                }
                case "dns":
                {
                    if (p.ValueKind != JsonValueKind.Object) return ("no data", 2);
                    var recs = new List<string>();
                    foreach (var key in new[] { "A", "AAAA" })
                        if (p.TryGetProperty(key, out var arr) && arr.ValueKind == JsonValueKind.Array)
                            foreach (var v in arr.EnumerateArray())
                                if (v.ValueKind == JsonValueKind.String) recs.Add(v.GetString() ?? "");
                    if (recs.Count == 0) return ("no records", 2);
                    string ttl = p.TryGetProperty("TTL", out var t) && t.ValueKind == JsonValueKind.Number ? $"  (TTL {t.GetRawText()})" : "";
                    return (string.Join(", ", recs.Take(4)) + (recs.Count > 4 ? "…" : "") + ttl, 1);
                }
            }
        }
        catch { }
        return ("parse error", 2);
    }

    private static string Ms(double seconds)
        => seconds >= 1 ? $"{seconds:0.00} s" : $"{seconds * 1000:0} ms";
}
