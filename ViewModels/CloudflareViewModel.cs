using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// Cloudflare: profiles (credentials + proxy) in a master-password vault, zones, DNS records (edit, backup / restore,
/// BIND import / export, DNSSEC), the zone settings a token can change (SSL/TLS incl. ECH and HSTS, security, speed,
/// network, cache, purge, pause), analytics, WAF custom rules, IP access rules, bots, redirects and edge certificates.
///
/// Split by area: this file = vault, profiles, account panel, API client, zones, status;
/// .Records = the record list + editor; .Backup = backup / BIND export / restore; .Settings = zone settings, HSTS,
/// I'm under attack, purge, pause; .Overview = the tabs (what each loads) + analytics; .Security = bots + IP access;
/// .Rules = custom rules + redirects (Rulesets API); .Ssl = edge certificates; .Dnssec = DNSSEC + BIND import;
/// .AddZone = add a site; .Models / .ZoneModels = the bound item classes.
/// </summary>
public partial class CloudflareViewModel : ObservableObject
{
    // Named profiles you can switch between; the active one drives every request.
    public ObservableCollection<CfProfile> Profiles { get; } = new();
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AccountSummary), nameof(AccountStatus), nameof(CanConnect), nameof(CanRetryConnect), nameof(EmptyTitle), nameof(EmptyText))]
    private CfProfile? _selectedProfile;

    // Master-password lock (mirrors the Notes tab). Profiles live in an encrypted vault.
    [ObservableProperty] private bool _isLocked = true;
    [ObservableProperty] private string _masterKey = string.Empty;
    [ObservableProperty] private string _unlockError = string.Empty;
    [ObservableProperty] private bool _hasVault;        // true: vault exists → "Unlock"; false: first run → "Set password"
    // Vault key + salt derived from the master password, cached for the unlocked SESSION so a save is
    // just AES-GCM + a file write instead of a fresh 600k PBKDF2 on the UI thread (mirrors Notes).
    private byte[]? _vaultKey;
    private byte[]? _vaultSalt;

    // An unlock's 600k-iteration PBKDF2 (twice for a first-run / legacy vault) runs on the thread pool — seconds on a
    // phone, which on the UI thread froze the window. Meanwhile the Unlock button reads "Unlocking…" and is disabled.
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UnlockLabel))]
    [NotifyCanExecuteChangedFor(nameof(UnlockCommand))]
    private bool _isUnlocking;
    public string UnlockLabel => IsUnlocking ? "Unlocking…" : "Unlock";
    // Bumped by lock / restore / a cleared session: an unlock still deriving at that moment is discarded when it lands.
    private int _unlockGen;

    /// <summary>A request that blocks the main actions is running (zones, records, saves, purge, restore…).</summary>
    [ObservableProperty] private bool _isBusy;
    private int _busyCount;

    [ObservableProperty] private string _statusMessage = "Enter your Cloudflare credentials to connect.";
    /// <summary>The status line shows a failure (danger tint).</summary>
    [ObservableProperty] private bool _statusIsError;

    /// <summary>The account form (add an account, or edit the active one) is open. Open on first run, when credentials
    /// are missing and after Cloudflare refused them; it folds away once the zones load. See .Accounts.</summary>
    [ObservableProperty] private bool _isAccountExpanded = true;

    public ObservableCollection<CfZone> Zones { get; } = new();
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasZone), nameof(ShowEmptyCard))]
    private CfZone? _selectedZone;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(AccountSummary), nameof(AccountStatus), nameof(CanRetryConnect), nameof(EmptyTitle), nameof(EmptyText))]
    private bool _isLoadingZones;

    public bool HasZone => SelectedZone != null;

    /// <summary>Why the last zone load failed: "" (it didn't) · "auth" · "nozones" · "other". Drives the empty page.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EmptyTitle), nameof(EmptyText), nameof(CanAddSiteFromEmpty), nameof(ConnectLabel))]
    private string _connectProblem = string.Empty;

    /// <summary>The token works but sees no zone: the empty page offers to add a site.</summary>
    public bool CanAddSiteFromEmpty => ConnectProblem == "nozones";

    // The page below the account panel before a zone is open.
    public string EmptyTitle => IsLoadingZones ? "Connecting to Cloudflare…"
        : ConnectProblem switch
        {
            "auth" => "Cloudflare refused these credentials",
            "nozones" => "This token can't see any zone",
            "other" => "Couldn't reach Cloudflare",
            _ => CanConnect ? "Not connected" : "Add your Cloudflare account",
        };

    public string EmptyText => IsLoadingZones ? "Loading the zones this token can see."
        : ConnectProblem switch
        {
            "auth" => "Edit the account and check its token and permissions (the ? in the form lists them).",
            "nozones" => "Give it Zone → Zone : Read on your zones and try again, or add a site.",
            "other" => "Check your connection or set a proxy (Edit), then try again. Details below.",
            _ => CanConnect
                ? "Connect to load this account's zones."
                : "Add an account above and paste an API token (the ? shows which one).",
        };

    /// <summary>0 Overview · 1 DNS · 2 SSL/TLS · 3 Security · 4 Speed & cache · 5 Network · 6 Rules. Each tab loads what
    /// it shows on first open per zone. The tab used last is remembered (DNS the first time).</summary>
    [ObservableProperty] private int _selectedTabIndex = TabDns;

    public const int TabOverview = 0, TabDns = 1, TabSsl = 2, TabSecurity = 3, TabSpeed = 4, TabNetwork = 5, TabRules = 6;

    public ObservableCollection<string> ProxyHistory => HistoryService.Instance.Get("cf.proxy");

    // Everything the current unlocked profile started (loads, edits) runs under this token; a lock or a profile switch
    // cancels it and bumps the generation so a late reply can't land in the next session.
    private CancellationTokenSource _sessionCts = new();
    private int _sessionGen;

    public CloudflareViewModel()
    {
        HasVault = !string.IsNullOrEmpty(ProfileService.Instance.GetSetting("cf.vault"));
        _lastTab = Math.Clamp(ProfileService.Instance.GetInt("cf.tab", TabDns), TabOverview, TabRules);
        _selectedTabIndex = _lastTab;
        RestoreSubTabs();
        Profiles.CollectionChanged += (_, e) =>
        {
            if (e.NewItems != null) foreach (CfProfile p in e.NewItems) p.PropertyChanged += OnProfileEdited;
            if (e.OldItems != null) foreach (CfProfile p in e.OldItems) p.PropertyChanged -= OnProfileEdited;
            // Reset = Clear(), used only when locking / reloading: never persist an emptied list.
            if (!IsLocked && e.Action != NotifyCollectionChangedAction.Reset) SaveProfiles();
            OnPropertyChanged(nameof(HasAccounts));
            OnPropertyChanged(nameof(CanCancelAccount));
        };
        Zones.CollectionChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(AccountSummary));
            OnPropertyChanged(nameof(AccountStatus));
        };
        // (CanBackup isn't raised per record: a zone's 20,000 records were 20,000 notices to every binding of this page.
        // What it reads, the zone, RecordsZoneId and IsLoadingRecords, raise it.)
        InitRecordEditor();
        AccessMode = AccessModeOptions[0];

        // Share one master password with Notes + Sync: auto-unlock if the app is already open.
        MasterSession.Changed += OnMasterSessionChanged;
        MasterSession.RestoreApplied += OnRestoreApplied;
        if (MasterSession.IsSet) _ = UnlockAsync(MasterSession.CopyPassword(), silent: true);
    }

    // A backup restore overwrote the cf.vault inside the profile. Drop stale in-memory profiles WITHOUT
    // saving (a save would re-encrypt them over the restored vault) and lock — the user re-unlocks.
    // Runs inline when already on the UI thread (the restore does): a debounced save already queued on the
    // dispatcher must then find us locked, instead of re-encrypting stale profiles over the restored vault.
    private void OnRestoreApplied()
    {
        if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess()) DropForRestore();
        else Avalonia.Threading.Dispatcher.UIThread.Post(DropForRestore);
    }

    private void DropForRestore()
    {
        IsLocked = true;              // set FIRST so Profiles.Clear()'s CollectionChanged handler won't save
        CancelUnlock();               // an unlock still deriving would apply the pre-restore vault
        _saveCts?.Cancel();
        _savePending = false;
        foreach (var p in Profiles) p.PropertyChanged -= OnProfileEdited;
        Profiles.Clear();
        ClearSession();
        SelectedProfile = null;
        IsAccountExpanded = false;    // drops the account form and the token / key typed into it (as LOCK does)
        ClearVaultKey();
        HasVault = !string.IsNullOrEmpty(ProfileService.Instance.GetSetting("cf.vault"));
    }

    private void ClearVaultKey()
    {
        SecureMemory.Release(_vaultKey);   // zeroed in place (pinned, so no stale copies elsewhere)
        _vaultKey = null;
        _vaultSalt = null;
    }

    private void OnMasterSessionChanged()
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            if (MasterSession.IsSet) { if (IsLocked) _ = UnlockAsync(MasterSession.CopyPassword(), silent: true); }
            else if (!IsLocked) LockInternal();   // session wiped → follow it
            else CancelUnlock();                  // ... including an unlock still deriving
        });
    }

    // Any edit to a profile's fields (token, proxy, name...) persists the whole vault.
    // Debounced: each save re-serializes the vault + AES-GCM + rewrites the whole profile file, so
    // persisting on every keystroke would lag typing and hammer the disk. Discrete actions below save immediately.
    private void OnProfileEdited(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (!IsLocked) SchedulePersist();
        if (ReferenceEquals(sender, SelectedProfile))
        {
            OnPropertyChanged(nameof(AccountSummary));
            OnPropertyChanged(nameof(AccountStatus));
            OnPropertyChanged(nameof(CanConnect));
            OnPropertyChanged(nameof(CanRetryConnect));
            OnPropertyChanged(nameof(EmptyTitle));
            OnPropertyChanged(nameof(EmptyText));
        }
    }

    private System.Threading.CancellationTokenSource? _saveCts;
    private bool _savePending;   // a debounced edit hasn't been written yet (UI thread only)

    private void SchedulePersist()
    {
        if (IsLocked || _vaultKey is null) return;
        _savePending = true;
        _saveCts?.Cancel();
        _saveCts?.Dispose();
        var cts = _saveCts = new System.Threading.CancellationTokenSource();
        _ = Task.Delay(450, cts.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(SaveProfiles);
        }, TaskScheduler.Default);
    }

    // Flush a pending debounced edit — called on app shutdown and when the app is backgrounded (Android may
    // kill it there without notice) so a just-typed change is never lost. No-op when nothing is pending.
    public void FlushPendingSave()
    {
        _saveCts?.Cancel();
        if (_savePending && !IsLocked) SaveProfiles();
    }

    partial void OnSelectedProfileChanged(CfProfile? value)
    {
        DeleteProfileConfirm = false;   // the question was about the profile that was selected
        if (IsLocked) return;
        SaveProfiles();   // persist the active selection
        // Another account: drop what the previous one loaded, then connect right away if it has credentials.
        ClearSession();
        if (value is null) return;
        // The form was editing the account switched away from: follow the switch (adding stays as it is).
        if (IsAccountExpanded && !IsAddingAccount) OpenAccountPanel(adding: false);
        if (value.HasCredentials) _ = LoadZonesAsync(keepZoneId: null);
        else
        {
            if (!IsAccountExpanded) OpenAccountPanel(adding: false);
            SetStatus("Add this account's API token to connect.");
        }
    }

    // ---------- Lock / unlock ----------
    [RelayCommand(CanExecute = nameof(CanUnlock))]
    private void Unlock() => _ = UnlockAsync(SecureMemory.CopyChars(MasterKey), silent: false);

    private bool CanUnlock() => !IsUnlocking;

    private void CancelUnlock()
    {
        _unlockGen++;
        IsUnlocking = false;
    }

    // Attempt to unlock the vault: decrypt / derive on the thread pool, apply on the UI thread. silent=true suppresses
    // the error text and leaves any current state untouched on failure (used by the shared-session auto-unlock — a
    // wrong password there just means Cloudflare uses a different master, so we quietly keep showing the prompt).
    // Takes ownership of the pinned password copy and zeroes it when the attempt is over.
    private async Task UnlockAsync(char[] password, bool silent)
    {
        try { await UnlockCoreAsync(password, silent); }
        finally { SecureMemory.Zero(password); }
    }

    private async Task UnlockCoreAsync(char[] password, bool silent)
    {
        if (IsUnlocking || !IsLocked) return;   // double click / Enter + click: the attempt in flight decides
        if (MemoryExtensions.IsWhiteSpace(password)) { if (!silent) UnlockError = "Enter a master password."; return; }

        int gen = ++_unlockGen;
        int epoch = MasterSession.Epoch;
        IsUnlocking = true;
        if (!silent) UnlockError = string.Empty;
        string? vault = ProfileService.Instance.GetSetting("cf.vault");

        // Decrypt/validate BEFORE mutating any state so a bad password is a no-op.
        VaultOpen result;
        try { result = await Task.Run(() => OpenVault(vault, password)); }
        catch (Exception ex) { result = VaultOpen.Fail("Error: " + ex.Message); }

        bool superseded = gen != _unlockGen;   // locked / restored here meanwhile (that already reset IsUnlocking)
        if (!superseded) IsUnlocking = false;
        if (superseded || epoch != MasterSession.Epoch)   // ... or LOCK / restore anywhere: never reopen what was just locked
        {
            result.Discard();
            return;
        }
        if (!result.Ok)
        {
            if (!silent) UnlockError = result.Error;
            // The shared session may have moved on while this ran (another area unlocked with another password).
            if (MasterSession.IsSet && !MasterSession.Matches(password)) _ = UnlockAsync(MasterSession.CopyPassword(), silent: true);
            return;
        }

        // Earlier builds always kept a placeholder profile ("Default", nothing filled in): accounts without credentials
        // are dropped, so an empty vault simply has no account and the form asks for the first one.
        int idx = ProfileService.Instance.GetInt("cf.activeIndex", 0);
        CfProfile? active = idx >= 0 && idx < result.Profiles.Count ? result.Profiles[idx] : null;
        Profiles.Clear();   // IsLocked still true → no save
        foreach (var p in result.Profiles)
            if (p.HasCredentials) Profiles.Add(p);
        // Profiles are already subscribed to OnProfileEdited via Profiles.CollectionChanged as
        // they're added above — no second subscription (that caused double saves per edit).

        ClearVaultKey();
        _vaultKey = result.Key;
        SecureMemory.Track(_vaultKey);   // wiped at exit if still unlocked
        _vaultSalt = result.Salt;
        SelectedProfile = active is not null && Profiles.Contains(active) ? active : Profiles.FirstOrDefault();

        IsLocked = false;
        HasVault = true;
        UnlockError = string.Empty;
        MasterKey = string.Empty;       // don't keep it in the bound textbox
        SaveProfiles();                 // writes the (now encrypted) vault; drops legacy copies
        MasterSession.Set(password);    // let Notes / Sync ride the same credential
        AfterUnlock();
    }

    // Result of an unlock attempt, built on the thread pool and applied on the UI thread.
    private sealed class VaultOpen
    {
        public bool Ok { get; init; }
        public string Error { get; init; } = string.Empty;
        public List<CfProfile> Profiles { get; init; } = new();
        public byte[]? Key { get; init; }
        public byte[]? Salt { get; init; }

        public static VaultOpen Fail(string error) => new() { Error = error };
        public void Discard() => SecureMemory.Zero(Key);
    }

    // Thread pool: the PBKDF2 work plus the profile parsing (the legacy format's SecretProtector values included).
    private static VaultOpen OpenVault(string? vault, char[] password)
    {
        byte[]? vaultJson = null, key = null, salt = null;
        if (!string.IsNullOrEmpty(vault) && !MasterVault.TryDecrypt(vault, password, out vaultJson, out key, out salt))
            return VaultOpen.Fail("Wrong master password.");

        var profiles = new List<CfProfile>();
        try
        {
            // The vault is parsed straight from its decrypted bytes (zeroed below), so no string holds the whole vault.
            if (vaultJson != null) profiles = ParseProfiles(JsonNode.Parse(vaultJson.AsSpan()), legacyDeviceEncrypted: false);
            else
            {
                // First run: this password becomes the master. Migrate any pre-vault profiles.
                var ps = ProfileService.Instance;
                var legacy = ps.GetSetting("cf.profiles");
                if (!string.IsNullOrEmpty(legacy)) profiles = ParseProfiles(JsonNode.Parse(legacy), legacyDeviceEncrypted: true);
                else if (LegacySingleProfile(ps) is { } single) profiles.Add(single);
            }
        }
        catch
        {
            SecureMemory.Zero(key);
            throw;
        }
        finally { SecureMemory.Zero(vaultJson); }

        // Keep the vault key for the session. A first-run or legacy (200k) vault has no reusable ECV1 key,
        // so derive a fresh salt + key once here; every later save reuses it.
        if (key is null || salt is null)
        {
            salt = RandomNumberGenerator.GetBytes(16);
            key = MasterVault.DeriveKey(password, salt);
        }
        return new VaultOpen { Ok = true, Profiles = profiles, Key = key, Salt = salt };
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
        // Lock BEFORE clearing: Profiles.Clear() and SelectedProfile = null raise change events whose handlers
        // save while unlocked, which used to encrypt an EMPTY list over cf.vault and wipe every stored profile.
        _saveCts?.Cancel();
        _savePending = false;
        CancelUnlock();
        IsLocked = true;
        ClearVaultKey();
        foreach (var p in Profiles) p.PropertyChanged -= OnProfileEdited;
        Profiles.Clear();
        ClearSession();
        SelectedProfile = null;
        IsAccountExpanded = false;      // drops the form and anything typed into it
        StatusMessage = "Locked.";
        StatusIsError = false;
    }

    // ---------- Removing an account (adding and editing: .Accounts) ----------

    /// <summary>The inline "remove this account?" strip is showing. A removal is saved to the vault at once and takes the
    /// account's API token / Global API key and proxy password with it (Cloudflare shows a token only when it's created),
    /// so it asks first like every other destructive action here.</summary>
    [ObservableProperty] private bool _deleteProfileConfirm;

    [RelayCommand]
    private void RequestDeleteProfile()
    {
        if (IsLocked || SelectedProfile == null) return;
        DeleteProfileConfirm = true;
    }

    [RelayCommand]
    private void CancelDeleteProfile() => DeleteProfileConfirm = false;

    /// <summary>The confirmation strip's Remove (only reachable after <see cref="RequestDeleteProfile"/>).</summary>
    [RelayCommand]
    private void DeleteProfile()
    {
        if (!DeleteProfileConfirm) return;
        DeleteProfileConfirm = false;
        if (IsLocked || SelectedProfile == null) return;
        string name = SelectedProfile.ToString();
        int idx = Profiles.IndexOf(SelectedProfile);
        IsAccountExpanded = false;
        Profiles.Remove(SelectedProfile);
        if (Profiles.Count == 0)
        {
            SelectedProfile = null;
            OpenAccountPanel(adding: true);
            SetStatus($"Account \"{name}\" removed. Add an account to continue.");
            return;
        }
        SelectedProfile = Profiles[System.Math.Clamp(idx, 0, Profiles.Count - 1)];   // connects to it
        if (!SelectedProfile.HasCredentials) SetStatus($"Account \"{name}\" removed.");
    }

    // Profiles from a JSON array (not yet attached to anything, so this runs on the thread pool).
    // legacyDeviceEncrypted = the old cf.profiles format whose secret fields were device-key encrypted
    // (SecretProtector); the vault format stores them plaintext-inside-the-encrypted-blob.
    private static List<CfProfile> ParseProfiles(JsonNode? root, bool legacyDeviceEncrypted)
    {
        var list = new List<CfProfile>();
        if (root is not JsonArray arr) return list;
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
            // lastZone arrived later: older vaults simply don't have it (= none). Only a well-formed id is kept.
            string lastZone = CfJson.Str(o["lastZone"]);
            var profile = new CfProfile
            {
                Name = (string?)o["name"] ?? "Profile",
                UseApiToken = (bool?)o["useToken"] ?? true,
                ApiToken = token,
                ApiEmail = (string?)o["email"] ?? string.Empty,
                ApiKey = key,
                UseProxy = (bool?)o["useProxy"] ?? false,
                ProxyAddress = (string?)o["proxy"] ?? string.Empty,
                ProxyUser = (string?)o["proxyUser"] ?? string.Empty,
                ProxyPass = ppass,
                LastZone = CloudflareApi.IsId(lastZone) ? lastZone.ToLowerInvariant() : string.Empty,
            };
            // uamPrev (later still): "zoneId=level;…". Re-set through the validator, so only well-formed entries stay.
            string prev = CfJson.Str(o["uamPrev"]);
            if (prev.Length is > 0 and <= 4096)
                foreach (string part in prev.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    if (part.IndexOf('=') is int eq and > 0) profile.SetPreviousLevel(part[..eq], part[(eq + 1)..]);
            list.Add(profile);
        }
        return list;
    }

    // Very old format: a single credential set stored as flat cf.* settings.
    private static CfProfile? LegacySingleProfile(ProfileService ps)
    {
        bool any = !string.IsNullOrEmpty(ps.GetSetting("cf.token"))
                || !string.IsNullOrEmpty(ps.GetSetting("cf.key"))
                || !string.IsNullOrEmpty(ps.GetSetting("cf.email"));
        if (!any) return null;
        return new CfProfile
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
        };
    }

    private void SaveProfiles()
    {
        if (IsLocked || _vaultKey is null || _vaultSalt is null) return;
        _savePending = false;

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
                ["proxyPass"] = p.ProxyPass,
                ["lastZone"] = p.LastZone,
                ["uamPrev"] = p.UnderAttackPrevious
            });

        int idx = SelectedProfile != null ? Profiles.IndexOf(SelectedProfile) : 0;
        var ps = ProfileService.Instance;
        ps.SetMany(
            ("cf.vault", EncryptVault(arr, _vaultKey, _vaultSalt)),
            ("cf.activeIndex", idx.ToString()));

        // Drop any pre-vault copies so secrets no longer linger unencrypted.
        foreach (var k in new[] { "cf.profiles", "cf.token", "cf.key", "cf.email",
                                  "cf.useToken", "cf.useProxy", "cf.proxy", "cf.proxyUser", "cf.proxyPass" })
            ps.Remove(k);
    }

    // The vault JSON is written as UTF-8 into a pinned buffer (no string of the whole vault, no GC-moved copies),
    // encrypted, and the buffer is zeroed. A vault too big for the buffer (dozens of profiles) falls back to a string.
    private static string EncryptVault(JsonArray profiles, byte[] key, byte[] salt)
    {
        byte[] buffer = SecureMemory.Alloc(64 * 1024);
        try
        {
            var sink = new PinnedBufferWriter(buffer);
            using (var w = new Utf8JsonWriter(sink)) profiles.WriteTo(w);
            return MasterVault.Encrypt(sink.WrittenSpan, key, salt);
        }
        catch (NotSupportedException)   // the fixed-size buffer is full
        {
            return MasterVault.Encrypt(profiles.ToJsonString(), key, salt);
        }
        finally { SecureMemory.Zero(buffer); }
    }

    // ---------- Account panel ----------

    /// <summary>"Personal · API token · 3 zones" — the collapsed account header.</summary>
    public string AccountSummary
    {
        get
        {
            var p = SelectedProfile;
            if (p is null) return "No profile";
            string name = string.IsNullOrWhiteSpace(p.Name) ? "Unnamed profile" : p.Name.Trim();
            string auth = p.UseApiToken ? "API token" : "Global API key";
            if (!p.HasCredentials) return $"{name} · no credentials yet";
            if (IsLoadingZones) return $"{name} · {auth} · connecting…";
            if (Zones.Count == 0) return $"{name} · {auth} · not connected";
            return $"{name} · {auth} · {Zones.Count} zone{(Zones.Count == 1 ? "" : "s")}";
        }
    }

    public bool CanConnect => SelectedProfile?.HasCredentials == true;

    // Unlocked: connect straight away when the active profile has credentials (and reopen the zone used last).
    private void AfterUnlock()
    {
        var p = SelectedProfile;
        if (p?.HasCredentials == true)
        {
            IsAccountExpanded = false;
            _ = LoadZonesAsync(keepZoneId: null);
        }
        else
        {
            OpenAccountPanel(adding: p is null);
            SetStatus(p is null ? "Unlocked. Add your Cloudflare account to start." : "Unlocked. Add this account's API token to connect.");
        }
    }

    // ---------- API client ----------

    private CloudflareApi? _api;
    private (CfProfile, bool, string, string, string, bool, string, string, string)? _apiFor;

    /// <summary>The client for the active profile's current credentials (kept while they don't change, so requests
    /// share one connection). Null with a readable <paramref name="error"/> when the credentials are unusable.</summary>
    private CloudflareApi? Api(out string error)
    {
        error = string.Empty;
        var p = SelectedProfile;
        if (IsLocked || p is null) { error = "Unlock and pick a profile first."; return null; }
        var key = (p, p.UseApiToken, p.ApiToken, p.ApiEmail, p.ApiKey, p.UseProxy, p.ProxyAddress, p.ProxyUser, p.ProxyPass);
        if (_api != null && _apiFor.Equals(key)) return _api;

        _api?.Dispose();
        _api = null;
        _apiFor = null;
        string? proxy = p.UseProxy && !string.IsNullOrWhiteSpace(p.ProxyAddress) ? p.ProxyAddress.Trim() : null;
        try
        {
            _api = CloudflareApi.Create(p.UseApiToken, p.ApiToken, p.ApiEmail, p.ApiKey,
                                        proxy, p.UseProxy ? p.ProxyUser : null, p.UseProxy ? p.ProxyPass : null);
        }
        catch (ArgumentException ex)
        {
            error = ex.Message;
            return null;
        }
        // Not with a user:password@ in it: the history is saved in plaintext, outside the vault (and .NET doesn't use
        // credentials written into the proxy address anyway — they go in the User / Password fields).
        if (proxy != null && !proxy.Contains('@')) HistoryService.Instance.Add("cf.proxy", proxy);
        _apiFor = key;
        return _api;
    }

    // Lock, restore or another profile: cancel everything in flight and forget what the last session loaded.
    private void ClearSession()
    {
        _sessionGen++;
        _sessionCts.Cancel();
        _sessionCts.Dispose();
        _sessionCts = new CancellationTokenSource();
        _api?.Dispose();
        _api = null;
        _apiFor = null;
        _busyCount = 0;
        IsBusy = false;
        IsLoadingZones = false;
        // A purge / pause cancelled here skips its own reset (its session is gone): left set, these kept Purge and
        // Pause disabled (and silently refused) for every zone until the app restarted.
        IsPurging = false;
        IsPausing = false;
        IsAddingAccess = false;
        IsSavingRule = false;
        IsAddingZone = false;
        IsLoadingAccounts = false;
        ConnectProblem = string.Empty;
        _settingsCache.Clear();
        _extrasCache.Clear();
        CloseRestore();
        CloseOverlays();
        IsEditorOpen = false;
        Zones.Clear();          // the zone picker drops its selection → SelectedZone = null clears the records
        SelectedZone = null;
        Records.Clear();
        RefreshVisible();
        CurrentSettings = null;
        CurrentExtras = null;
        Accounts.Clear();
        SelectedTabIndex = _lastTab;
    }

    private void BeginBusy()
    {
        _busyCount++;
        IsBusy = true;
    }

    private void EndBusy(int gen)
    {
        if (gen != _sessionGen) return;   // that session was cleared (and its counter with it)
        _busyCount = Math.Max(0, _busyCount - 1);
        IsBusy = _busyCount > 0;
    }

    private void SetStatus(string message)
    {
        StatusMessage = message;
        StatusIsError = false;
    }

    private void SetError(string message)
    {
        StatusMessage = message;
        StatusIsError = true;
    }

    // ---------- Zones ----------

    /// <summary>Load (or reload) the zones of the active profile. Also the account panel's "Load zones" button.</summary>
    [RelayCommand]
    private Task LoadZones() => LoadZonesAsync(keepZoneId: SelectedZone?.Id);

    /// <summary>The refresh icon by the zone picker: zones (status, plan, name servers), then everything of the open zone
    /// (records, and what the open tab shows: settings, rules, certificates… — read again, not from the session cache).</summary>
    [RelayCommand]
    private Task Refresh()
    {
        if (SelectedZone is { } zone && !IsLoadingZones)
        {
            // parts with a change in flight stay (their answer still lands); everything else is read again
            if (_settingsCache.TryGetValue(zone.Id, out var s) && !s.All.Any(x => x.IsBusy) && !s.Hsts.IsBusy) _settingsCache.Remove(zone.Id);
            _extrasCache.Remove(zone.Id);
        }
        return LoadZonesAsync(keepZoneId: SelectedZone?.Id);
    }

    private async Task LoadZonesAsync(string? keepZoneId)
    {
        if (IsLocked || IsLoadingZones) return;
        var profile = SelectedProfile;
        if (profile is null) return;
        if (!profile.HasCredentials)
        {
            if (!IsAccountExpanded || IsAddingAccount) OpenAccountPanel(adding: false);
            SetError(profile.UseApiToken ? "Enter an API token first." : "Enter your account email and Global API key first.");
            return;
        }
        var api = Api(out string error);
        if (api is null)
        {
            if (!IsAccountExpanded || IsAddingAccount) OpenAccountPanel(adding: false);
            AccountError = error;
            ConnectProblem = "other";
            SetError(error);
            return;
        }

        int gen = _sessionGen;
        var ct = _sessionCts.Token;
        ConnectProblem = string.Empty;
        IsLoadingZones = true;
        BeginBusy();
        SetStatus("Loading zones…");
        CfListResponse r;
        try { r = await api.GetAllAsync("/zones", 50, CfPermission.ZoneRead, ct); }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (gen == _sessionGen) IsLoadingZones = false;
            EndBusy(gen);
        }
        if (gen != _sessionGen || IsLocked || !ReferenceEquals(profile, SelectedProfile)) return;

        if (!r.Success)
        {
            ConnectProblem = r.AuthFailed ? "auth" : "other";
            SetError("Couldn't load your zones: " + r.Error);
            // Refused: the credentials are what to fix, so the form opens on them. No connection: the empty page says so
            // and offers "Try again" (Edit gives the account a proxy).
            if (r.AuthFailed)
            {
                if (!IsAccountExpanded || IsAddingAccount) OpenAccountPanel(adding: false);
                AccountError = CheckFailure(r.Error, refused: true);
            }
            return;
        }

        var zones = r.Items.Select(CfZone.FromApi).OfType<CfZone>()
                           .OrderBy(z => z.Name, StringComparer.OrdinalIgnoreCase).ToList();
        Zones.Clear();
        foreach (var z in zones) Zones.Add(z);
        OnPropertyChanged(nameof(AccountSummary));

        if (zones.Count == 0)
        {
            IsAccountExpanded = false;   // the credentials work: the empty page explains it and offers "Add a site"
            ConnectProblem = "nozones";
            SelectedZone = null;
            SetError("0 zones. The token works but can't list zones: it needs the Zone → Zone : Read permission, "
                     + "with Zone Resources including your zones (All zones, or the ones you pick).");
            return;
        }

        IsAccountExpanded = false;
        string? want = keepZoneId ?? (CloudflareApi.IsId(profile.LastZone) ? profile.LastZone : null);
        SelectedZone = zones.FirstOrDefault(z => z.Id == want) ?? zones[0];   // → loads its records
        if (r.Truncated) SetError($"Showing the first {zones.Count} zones only.");
    }

    partial void OnSelectedZoneChanged(CfZone? value)
    {
        ResetZoneScopedUi();
        CurrentSettings = value is null ? null : SettingsFor(value);
        CurrentExtras = value is null ? null : ExtrasFor(value);
        OnPropertyChanged(nameof(CurrentAnalytics));
        OnPropertyChanged(nameof(CanBackup));
        if (value is null || IsLocked) return;

        // Remember it for this profile (saved with the vault, reselected after the next unlock).
        if (SelectedProfile is { } p && p.LastZone != value.Id) p.LastZone = value.Id;
        // A reloaded zone list holds new objects: carry over what the zone line shows from the cached parts.
        if (_settingsCache.TryGetValue(value.Id, out var known) && known.IsLoaded) value.UnderAttack = known.SecurityLevel.Value == "under_attack";
        _ = LoadRecordsAsync(value);
        _ = EnsureDnssecAsync(value, force: false);   // the zone line's DNSSEC chip
        EnsureTabData();
    }

    partial void OnSelectedTabIndexChanged(int value)
    {
        if (value is < TabOverview or > TabRules) return;
        if (value != _lastTab)
        {
            _lastTab = value;
            ProfileService.Instance.SetSetting("cf.tab", value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        EnsureTabData();
    }

    /// <summary>Copy the zone's Cloudflare name servers (one per line) — what to set at the registrar.</summary>
    [RelayCommand]
    private async Task CopyNameServers()
    {
        if (SelectedZone is not { HasNameServers: true } zone) return;
        try
        {
            await ClipboardHelper.SetTextAsync(string.Join(Environment.NewLine, zone.NameServers));
            SetStatus($"Name servers of {zone.Name} copied.");
        }
        catch (Exception ex) { SetError("Couldn't copy: " + ex.Message); }
    }
}
