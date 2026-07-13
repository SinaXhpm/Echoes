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

/// <summary>A named Cloudflare connection profile: one set of credentials + its proxy.</summary>
public partial class CfProfile : ObservableObject
{
    [ObservableProperty] private string _name = "Profile";
    // Auth — true: API Token (Bearer); false: Global API Key + email
    [ObservableProperty] private bool _useApiToken = true;
    [ObservableProperty] private string _apiToken = string.Empty;
    [ObservableProperty] private string _apiEmail = string.Empty;
    [ObservableProperty] private string _apiKey = string.Empty;
    // Proxy (per profile)
    [ObservableProperty] private bool _useProxy;
    [ObservableProperty] private string _proxyAddress = string.Empty;
    [ObservableProperty] private string _proxyUser = string.Empty;
    [ObservableProperty] private string _proxyPass = string.Empty;

    public override string ToString() => string.IsNullOrWhiteSpace(Name) ? "(unnamed)" : Name;
}

public partial class CloudflareViewModel : ObservableObject
{
    private const string Api = "https://api.cloudflare.com/client/v4";

    // Named profiles you can switch between; the active one drives every request.
    public ObservableCollection<CfProfile> Profiles { get; } = new();
    [ObservableProperty] private CfProfile? _selectedProfile;

    // Master-password lock (mirrors the Notes tab). Profiles live in an encrypted vault.
    [ObservableProperty] private bool _isLocked = true;
    [ObservableProperty] private string _masterKey = string.Empty;
    [ObservableProperty] private string _unlockError = string.Empty;
    [ObservableProperty] private bool _hasVault;        // true: vault exists → "Unlock"; false: first run → "Set password"
    private string _master = string.Empty;              // active password, kept while unlocked to re-encrypt on save

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

    public CloudflareViewModel()
    {
        HasVault = !string.IsNullOrEmpty(ProfileService.Instance.GetSetting("cf.vault"));
        Profiles.CollectionChanged += (_, e) =>
        {
            if (e.NewItems != null) foreach (CfProfile p in e.NewItems) p.PropertyChanged += OnProfileEdited;
            if (e.OldItems != null) foreach (CfProfile p in e.OldItems) p.PropertyChanged -= OnProfileEdited;
            if (!IsLocked) SaveProfiles();
        };

        // Share one master password with Notes + Sync: auto-unlock if the app is already open.
        MasterSession.Changed += OnMasterSessionChanged;
        if (MasterSession.IsSet) TryUnlock(MasterSession.Password, silent: true);
    }

    private void OnMasterSessionChanged()
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            if (MasterSession.IsSet && IsLocked) TryUnlock(MasterSession.Password, silent: true);
            else if (!MasterSession.IsSet && !IsLocked) LockInternal();  // session wiped → follow it
        });
    }

    // Any edit to a profile's fields (token, proxy, name...) persists the whole vault.
    // Debounced: each save runs PBKDF2 (200k) + AES-GCM + a file write, so persisting on every
    // keystroke would lag typing and hammer the disk. Discrete actions below save immediately.
    private void OnProfileEdited(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (!IsLocked) SchedulePersist();
    }

    private System.Threading.CancellationTokenSource? _saveCts;

    private void SchedulePersist()
    {
        if (IsLocked || string.IsNullOrEmpty(_master)) return;
        _saveCts?.Cancel();
        _saveCts?.Dispose();
        var cts = _saveCts = new System.Threading.CancellationTokenSource();
        _ = Task.Delay(450, cts.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(SaveProfiles);
        }, TaskScheduler.Default);
    }

    // Flush a pending debounced edit — called on app shutdown so a just-typed change is never lost.
    public void FlushPendingSave()
    {
        _saveCts?.Cancel();
        if (!IsLocked) SaveProfiles();
    }

    partial void OnSelectedProfileChanged(CfProfile? value)
    {
        if (!IsLocked) SaveProfiles();   // persist the active selection
    }

    // ---------- Lock / unlock ----------
    [RelayCommand]
    private void Unlock() => TryUnlock(MasterKey, silent: false);

    // Attempt to unlock the vault. silent=true suppresses the error text and leaves any current
    // state untouched on failure (used by the shared-session auto-unlock — a wrong password there
    // just means Cloudflare uses a different master, so we quietly keep showing the manual prompt).
    private bool TryUnlock(string password, bool silent)
    {
        if (string.IsNullOrWhiteSpace(password)) { if (!silent) UnlockError = "Enter a master password."; return false; }

        var ps = ProfileService.Instance;
        var vault = ps.GetSetting("cf.vault");

        // Decrypt/validate BEFORE mutating any state so a bad password is a no-op.
        string? vaultJson = null;
        if (!string.IsNullOrEmpty(vault))
        {
            if (!MasterVault.TryDecrypt(vault, password, out vaultJson))
            { if (!silent) UnlockError = "Wrong master password."; return false; }
        }

        Profiles.Clear();   // IsLocked still true → no save

        if (vaultJson != null)
        {
            LoadProfilesFromJson(vaultJson, legacyDeviceEncrypted: false);
        }
        else
        {
            // First run: this password becomes the master. Migrate any pre-vault profiles.
            var legacy = ps.GetSetting("cf.profiles");
            if (!string.IsNullOrEmpty(legacy)) LoadProfilesFromJson(legacy, legacyDeviceEncrypted: true);
            else MigrateLegacySingle(ps);
        }

        if (Profiles.Count == 0) Profiles.Add(new CfProfile { Name = "Default" });
        // Profiles are already subscribed to OnProfileEdited via Profiles.CollectionChanged as
        // they're added above — no second subscription (that caused double saves per edit).

        _master = password;
        int idx = ps.GetInt("cf.activeIndex", 0);
        SelectedProfile = Profiles[System.Math.Clamp(idx, 0, Profiles.Count - 1)];

        IsLocked = false;
        HasVault = true;
        UnlockError = string.Empty;
        MasterKey = string.Empty;       // don't keep it in the bound textbox
        SaveProfiles();                 // writes the (now encrypted) vault; drops legacy copies
        StatusMessage = "Unlocked. Load your zones.";
        MasterSession.Set(password);    // let Notes / Sync ride the same credential
        return true;
    }

    // User pressed LOCK: lock this tab AND drop the shared session so Notes/Sync re-lock too.
    [RelayCommand]
    private void LockApp()
    {
        LockInternal();
        MasterSession.Clear();
    }

    private void LockInternal()
    {
        if (!IsLocked) SaveProfiles();
        foreach (var p in Profiles) p.PropertyChanged -= OnProfileEdited;
        Profiles.Clear();
        Zones.Clear();
        Records.Clear();
        SelectedProfile = null;
        _master = string.Empty;
        IsLocked = true;
        IsEditorOpen = false;
        StatusMessage = "Locked.";
    }

    // ---------- Profile management ----------
    [RelayCommand]
    private void AddProfile()
    {
        if (IsLocked) return;
        var p = new CfProfile { Name = $"Profile {Profiles.Count + 1}" };
        Profiles.Add(p);
        SelectedProfile = p;
        StatusMessage = "New profile added — fill in its credentials.";
    }

    [RelayCommand]
    private void DeleteProfile()
    {
        if (IsLocked || SelectedProfile == null) return;
        int idx = Profiles.IndexOf(SelectedProfile);
        Profiles.Remove(SelectedProfile);
        if (Profiles.Count == 0) Profiles.Add(new CfProfile { Name = "Default" });
        SelectedProfile = Profiles[System.Math.Clamp(idx, 0, Profiles.Count - 1)];
        StatusMessage = "Profile deleted.";
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

    // Populate Profiles from a JSON array. legacyDeviceEncrypted = the old cf.profiles format
    // whose secret fields were device-key encrypted (SecretProtector); the vault format stores
    // them plaintext-inside-the-encrypted-blob.
    private void LoadProfilesFromJson(string json, bool legacyDeviceEncrypted)
    {
        if (JsonNode.Parse(json) is not JsonArray arr) return;
        foreach (var n in arr)
        {
            if (n is not JsonObject o) continue;
            string token = (string?)o["token"] ?? string.Empty;
            string key = (string?)o["key"] ?? string.Empty;
            string ppass = (string?)o["proxyPass"] ?? string.Empty;
            if (legacyDeviceEncrypted)
            {
                token = SecretProtector.Unprotect(token);
                key = SecretProtector.Unprotect(key);
                ppass = SecretProtector.Unprotect(ppass);
            }
            Profiles.Add(new CfProfile
            {
                Name = (string?)o["name"] ?? "Profile",
                UseApiToken = (bool?)o["useToken"] ?? true,
                ApiToken = token,
                ApiEmail = (string?)o["email"] ?? string.Empty,
                ApiKey = key,
                UseProxy = (bool?)o["useProxy"] ?? false,
                ProxyAddress = (string?)o["proxy"] ?? string.Empty,
                ProxyUser = (string?)o["proxyUser"] ?? string.Empty,
                ProxyPass = ppass
            });
        }
    }

    // Very old format: a single credential set stored as flat cf.* settings.
    private void MigrateLegacySingle(ProfileService ps)
    {
        bool any = !string.IsNullOrEmpty(ps.GetSetting("cf.token"))
                || !string.IsNullOrEmpty(ps.GetSetting("cf.key"))
                || !string.IsNullOrEmpty(ps.GetSetting("cf.email"));
        if (!any) return;
        Profiles.Add(new CfProfile
        {
            Name = "Default",
            UseApiToken = ps.GetBool("cf.useToken", true),
            ApiToken = ps.GetSetting("cf.token") ?? string.Empty,
            ApiEmail = ps.GetSetting("cf.email") ?? string.Empty,
            ApiKey = ps.GetSetting("cf.key") ?? string.Empty,
            UseProxy = ps.GetBool("cf.useProxy", false),
            ProxyAddress = ps.GetSetting("cf.proxy") ?? string.Empty,
            ProxyUser = ps.GetSetting("cf.proxyUser") ?? string.Empty,
            ProxyPass = ps.GetSetting("cf.proxyPass") ?? string.Empty
        });
    }

    private void SaveProfiles()
    {
        if (IsLocked || string.IsNullOrEmpty(_master)) return;

        var arr = new JsonArray();
        foreach (var p in Profiles)
            // Cast to JsonNode so the non-generic Add(JsonNode?) is chosen (AOT-safe;
            // the generic Add<T> is RequiresDynamicCode).
            arr.Add((JsonNode)new JsonObject
            {
                ["name"] = p.Name,
                ["useToken"] = p.UseApiToken,
                ["token"] = p.ApiToken,        // plaintext inside the master-encrypted vault
                ["email"] = p.ApiEmail,
                ["key"] = p.ApiKey,
                ["useProxy"] = p.UseProxy,
                ["proxy"] = p.ProxyAddress,
                ["proxyUser"] = p.ProxyUser,
                ["proxyPass"] = p.ProxyPass
            });

        int idx = SelectedProfile != null ? Profiles.IndexOf(SelectedProfile) : 0;
        var ps = ProfileService.Instance;
        ps.SetMany(
            ("cf.vault", MasterVault.Encrypt(arr.ToJsonString(), _master)),
            ("cf.activeIndex", idx.ToString()));

        // Drop any pre-vault copies so secrets no longer linger unencrypted.
        foreach (var k in new[] { "cf.profiles", "cf.token", "cf.key", "cf.email",
                                  "cf.useToken", "cf.useProxy", "cf.proxy", "cf.proxyUser", "cf.proxyPass" })
            ps.Remove(k);
    }

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
        var p = SelectedProfile;
        if (p == null) { StatusMessage = "Add a profile first."; return false; }
        if (p.UseApiToken)
        {
            if (string.IsNullOrWhiteSpace(p.ApiToken)) { StatusMessage = "Enter an API token."; return false; }
        }
        else if (string.IsNullOrWhiteSpace(p.ApiEmail) || string.IsNullOrWhiteSpace(p.ApiKey))
        {
            StatusMessage = "Enter your account email and Global API key."; return false;
        }
        return true;
    }

    private HttpClient CreateClient()
    {
        var p = SelectedProfile ?? new CfProfile();
        string? proxy = p.UseProxy && !string.IsNullOrWhiteSpace(p.ProxyAddress) ? p.ProxyAddress : null;
        if (proxy != null) HistoryService.Instance.Add("cf.proxy", proxy);

        var c = HttpHelper.Create(proxy, p.ProxyUser, p.ProxyPass, timeout: TimeSpan.FromSeconds(25));
        c.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        if (p.UseApiToken)
            c.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", "Bearer " + p.ApiToken.Trim());
        else
        {
            c.DefaultRequestHeaders.TryAddWithoutValidation("X-Auth-Email", p.ApiEmail.Trim());
            c.DefaultRequestHeaders.TryAddWithoutValidation("X-Auth-Key", p.ApiKey.Trim());
        }
        return c;
    }

    private static string FirstError(JsonElement root)
    {
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0)
        {
            var msgs = new System.Collections.Generic.List<string>();
            foreach (var e in errs.EnumerateArray())
            {
                string msg = e.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
                int code = e.TryGetProperty("code", out var cc) && cc.ValueKind == JsonValueKind.Number ? cc.GetInt32() : 0;
                if (!string.IsNullOrWhiteSpace(msg)) msgs.Add(code != 0 ? $"{msg} (code {code})" : msg);
            }
            if (msgs.Count > 0) return string.Join("; ", msgs);
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
                using var resp = await c.GetAsync($"{Api}/zones?per_page=50&page={page}");
                var text = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                if (!root.TryGetProperty("success", out var ok) || !ok.GetBoolean())
                {
                    StatusMessage = $"Error (HTTP {(int)resp.StatusCode}): {FirstError(root)}";
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

            SaveProfiles();
            StatusMessage = Zones.Count > 0
                ? $"Loaded {Zones.Count} zone(s). Pick a domain to see its records."
                : "0 zones. The token works but can't list zones — it needs the Zone → Zone → Read "
                  + "permission, with Zone Resources set to include your zones (All zones, or the specific ones).";
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
                using var resp = await c.GetAsync($"{Api}/zones/{zone.Id}/dns_records?per_page=100&page={page}");
                var text = await resp.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;
                if (!root.TryGetProperty("success", out var ok) || !ok.GetBoolean())
                {
                    string err = FirstError(root);
                    // 10000/9109 here = the token can list zones but lacks DNS access on this zone.
                    if (err.Contains("10000") || err.Contains("9109"))
                        err += " — the token needs the Zone → DNS → Edit (or Read) permission for this zone.";
                    StatusMessage = $"Error (HTTP {(int)resp.StatusCode}): {err}";
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
            using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            bool creating = string.IsNullOrEmpty(EditRecordId);
            using var resp = creating
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
            using var resp = await c.DeleteAsync($"{Api}/zones/{SelectedZone.Id}/dns_records/{EditRecordId}");
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
