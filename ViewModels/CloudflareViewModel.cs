using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.ObjectModel;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

public class CfZone
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public override string ToString() => Name;
}

public class CfRecord
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public int Ttl { get; set; } = 1;
    public bool Proxied { get; set; }
    public int Priority { get; set; }
    // For the list UI
    public string TtlText => Ttl <= 1 ? "auto" : Ttl.ToString();
    public string ProxiedText => Proxied ? "proxied" : "dns-only";
}

public partial class CloudflareViewModel : ObservableObject
{
    private const string Api = "https://api.cloudflare.com/client/v4";

    // Auth — true: API Token (Bearer); false: Global API Key + email
    [ObservableProperty] private bool _useApiToken = true;
    [ObservableProperty] private string _apiToken = string.Empty;
    [ObservableProperty] private string _apiEmail = string.Empty;
    [ObservableProperty] private string _apiKey = string.Empty;

    // Proxy (for every request)
    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private bool _isEditorOpen;
    [ObservableProperty] private string _statusMessage = "Enter your Cloudflare credentials and load your zones.";

    public ObservableCollection<CfZone> Zones { get; } = new();
    public ObservableCollection<CfRecord> Records { get; } = new();
    [ObservableProperty] private CfZone? _selectedZone;
    [ObservableProperty] private CfRecord? _selectedRecord;

    // Record editor
    public string[] RecordTypes { get; } = { "A", "AAAA", "CNAME", "TXT", "MX", "NS" };
    [ObservableProperty] private string _editRecordId = string.Empty;
    [ObservableProperty] private string _editType = "A";
    [ObservableProperty] private string _editName = string.Empty;
    [ObservableProperty] private string _editContent = string.Empty;
    [ObservableProperty] private int _editTtl = 1;
    [ObservableProperty] private int _editPriority = 10;
    [ObservableProperty] private bool _editProxied;

    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("cf.proxy");

    private bool _loaded;
    private static readonly System.Collections.Generic.HashSet<string> PersistProps = new()
    { "UseApiToken", "ApiToken", "ApiEmail", "ApiKey", "UseProxy", "ProxyAddress", "ProxyUser", "ProxyPass" };

    public CloudflareViewModel()
    {
        LoadCreds();
        if (string.IsNullOrWhiteSpace(ProxyAddress) && HistoryService.Instance.Last("cf.proxy") is { } p)
            ProxyAddress = p;
        _loaded = true;
    }

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n)) SaveCreds();
    }

    partial void OnSelectedZoneChanged(CfZone? value)
    {
        if (value != null) _ = LoadRecords(value);
    }

    // Selecting a record only stages its values; the editor opens via ADD/EDIT.
    partial void OnSelectedRecordChanged(CfRecord? value)
    {
        if (value == null) return;
        EditRecordId = value.Id;
        EditType = value.Type;
        EditName = value.Name;
        EditContent = value.Content;
        EditTtl = value.Ttl;
        EditProxied = value.Proxied;
        EditPriority = value.Priority;
    }

    private void LoadCreds()
    {
        var ps = ProfileService.Instance;
        UseApiToken = ps.GetBool("cf.useToken", true);
        ApiToken = ps.GetSetting("cf.token") ?? string.Empty;
        ApiEmail = ps.GetSetting("cf.email") ?? string.Empty;
        ApiKey = ps.GetSetting("cf.key") ?? string.Empty;
        UseProxy = ps.GetBool("cf.useProxy", false);
        ProxyAddress = ps.GetSetting("cf.proxy") ?? string.Empty;
        ProxyUser = ps.GetSetting("cf.proxyUser") ?? string.Empty;
        ProxyPass = ps.GetSetting("cf.proxyPass") ?? string.Empty;
    }

    private void SaveCreds()
        => ProfileService.Instance.SetMany(
            ("cf.useToken", UseApiToken ? "true" : "false"), ("cf.token", ApiToken),
            ("cf.email", ApiEmail), ("cf.key", ApiKey),
            ("cf.useProxy", UseProxy ? "true" : "false"), ("cf.proxy", ProxyAddress),
            ("cf.proxyUser", ProxyUser), ("cf.proxyPass", ProxyPass));

    private void ClearEditFields()
    {
        EditRecordId = string.Empty;
        EditType = "A";
        EditName = string.Empty;
        EditContent = string.Empty;
        EditTtl = 1;
        EditPriority = 10;
        EditProxied = false;
    }

    [RelayCommand]
    private void EditSelected()
    {
        if (SelectedRecord == null) { StatusMessage = "Select a record first, then press EDIT."; return; }
        IsEditorOpen = true;
    }

    [RelayCommand]
    private void CancelEdit() => IsEditorOpen = false;

    private bool ValidateAuth()
    {
        if (UseApiToken)
        {
            if (string.IsNullOrWhiteSpace(ApiToken)) { StatusMessage = "Enter an API token."; return false; }
        }
        else if (string.IsNullOrWhiteSpace(ApiEmail) || string.IsNullOrWhiteSpace(ApiKey))
        {
            StatusMessage = "Enter your account email and Global API key."; return false;
        }
        return true;
    }

    private HttpClient CreateClient()
    {
        string? proxy = UseProxy && !string.IsNullOrWhiteSpace(ProxyAddress) ? ProxyAddress : null;
        if (proxy != null) HistoryService.Instance.Add("cf.proxy", proxy);

        var c = HttpHelper.Create(proxy, ProxyUser, ProxyPass, timeout: TimeSpan.FromSeconds(25));
        c.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        if (UseApiToken)
            c.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + ApiToken.Trim());
        else
        {
            c.DefaultRequestHeaders.TryAddWithoutValidation("X-Auth-Email", ApiEmail.Trim());
            c.DefaultRequestHeaders.TryAddWithoutValidation("X-Auth-Key", ApiKey.Trim());
        }
        return c;
    }

    private static string FirstError(JsonElement root)
    {
        if (root.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0)
        {
            var e0 = errs[0];
            string msg = e0.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
            int code = e0.TryGetProperty("code", out var cc) && cc.ValueKind == JsonValueKind.Number ? cc.GetInt32() : 0;
            return code != 0 ? $"{msg} (code {code})" : msg;
        }
        return "request failed";
    }

    [RelayCommand]
    private async Task LoadZones()
    {
        if (!ValidateAuth()) return;
        IsBusy = true;
        StatusMessage = "Loading zones...";
        try
        {
            using var c = CreateClient();
            Zones.Clear();
            Records.Clear();
            int page = 1, totalPages = 1;
            do
            {
                var resp = await c.GetAsync($"{Api}/zones?per_page=50&page={page}");
                var text = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                if (!root.TryGetProperty("success", out var ok) || !ok.GetBoolean())
                {
                    StatusMessage = "Error: " + FirstError(root);
                    IsBusy = false;
                    return;
                }
                foreach (var z in root.GetProperty("result").EnumerateArray())
                {
                    Zones.Add(new CfZone
                    {
                        Id = z.GetProperty("id").GetString() ?? "",
                        Name = z.GetProperty("name").GetString() ?? "",
                        Status = z.TryGetProperty("status", out var st) ? st.GetString() ?? "" : ""
                    });
                }
                if (root.TryGetProperty("result_info", out var info) && info.TryGetProperty("total_pages", out var tp))
                    totalPages = tp.GetInt32();
                page++;
            } while (page <= totalPages);

            SaveCreds();
            StatusMessage = $"Loaded {Zones.Count} zone(s). Pick a domain to see its records.";
        }
        catch (Exception ex) { StatusMessage = "Error: " + ex.Message; }
        IsBusy = false;
    }

    [RelayCommand]
    private async Task ReloadRecords()
    {
        if (SelectedZone != null) await LoadRecords(SelectedZone);
    }

    private async Task LoadRecords(CfZone zone)
    {
        IsBusy = true;
        StatusMessage = $"Loading DNS records for {zone.Name}...";
        try
        {
            using var c = CreateClient();
            Records.Clear();
            int page = 1, totalPages = 1;
            do
            {
                var resp = await c.GetAsync($"{Api}/zones/{zone.Id}/dns_records?per_page=100&page={page}");
                var text = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                if (!root.TryGetProperty("success", out var ok) || !ok.GetBoolean())
                {
                    StatusMessage = "Error: " + FirstError(root);
                    IsBusy = false;
                    return;
                }
                foreach (var r in root.GetProperty("result").EnumerateArray())
                {
                    Records.Add(new CfRecord
                    {
                        Id = r.GetProperty("id").GetString() ?? "",
                        Type = r.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "",
                        Name = r.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                        Content = r.TryGetProperty("content", out var ct) ? ct.GetString() ?? "" : "",
                        Ttl = r.TryGetProperty("ttl", out var tt) && tt.ValueKind == JsonValueKind.Number ? tt.GetInt32() : 1,
                        Proxied = r.TryGetProperty("proxied", out var px) && px.ValueKind == JsonValueKind.True,
                        Priority = r.TryGetProperty("priority", out var pr) && pr.ValueKind == JsonValueKind.Number ? pr.GetInt32() : 0
                    });
                }
                if (root.TryGetProperty("result_info", out var info) && info.TryGetProperty("total_pages", out var tp))
                    totalPages = tp.GetInt32();
                page++;
            } while (page <= totalPages);

            StatusMessage = $"{zone.Name}: {Records.Count} record(s).";
        }
        catch (Exception ex) { StatusMessage = "Error: " + ex.Message; }
        IsBusy = false;
    }

    [RelayCommand]
    private void NewRecord()
    {
        SelectedRecord = null;
        ClearEditFields();
        IsEditorOpen = true;
        StatusMessage = "New record — fill the fields and press SAVE.";
    }

    [RelayCommand]
    private async Task SaveRecord()
    {
        if (SelectedZone == null) { StatusMessage = "Select a zone first."; return; }
        if (string.IsNullOrWhiteSpace(EditName) || string.IsNullOrWhiteSpace(EditContent))
        { StatusMessage = "Name and content are required."; return; }

        IsBusy = true;
        try
        {
            var body = new JsonObject
            {
                ["type"] = EditType,
                ["name"] = EditName.Trim(),
                ["content"] = EditContent.Trim(),
                ["ttl"] = EditTtl < 1 ? 1 : EditTtl
            };
            if (EditType is "A" or "AAAA" or "CNAME") body["proxied"] = EditProxied;
            if (EditType == "MX") body["priority"] = EditPriority;

            using var c = CreateClient();
            var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            bool creating = string.IsNullOrEmpty(EditRecordId);
            var resp = creating
                ? await c.PostAsync($"{Api}/zones/{SelectedZone.Id}/dns_records", content)
                : await c.PutAsync($"{Api}/zones/{SelectedZone.Id}/dns_records/{EditRecordId}", content);

            var text = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("success", out var ok) && ok.GetBoolean())
            {
                StatusMessage = creating ? "Record created." : "Record updated.";
                IsEditorOpen = false;
                await LoadRecords(SelectedZone);
            }
            else StatusMessage = "Error: " + FirstError(doc.RootElement);
        }
        catch (Exception ex) { StatusMessage = "Error: " + ex.Message; }
        IsBusy = false;
    }

    [RelayCommand]
    private async Task DeleteRecord()
    {
        if (SelectedZone == null || string.IsNullOrEmpty(EditRecordId))
        { StatusMessage = "Select a record to delete."; return; }

        IsBusy = true;
        try
        {
            using var c = CreateClient();
            var resp = await c.DeleteAsync($"{Api}/zones/{SelectedZone.Id}/dns_records/{EditRecordId}");
            var text = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("success", out var ok) && ok.GetBoolean())
            {
                StatusMessage = "Record deleted.";
                ClearEditFields();
                IsEditorOpen = false;
                await LoadRecords(SelectedZone);
            }
            else StatusMessage = "Error: " + FirstError(doc.RootElement);
        }
        catch (Exception ex) { StatusMessage = "Error: " + ex.Message; }
        IsBusy = false;
    }
}
