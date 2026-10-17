using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>Where a dynamic-DNS record stands.</summary>
public enum DdnsState
{
    /// <summary>Added, not checked yet.</summary>
    Pending,
    /// <summary>The record holds this device's public IP.</summary>
    UpToDate,
    /// <summary>The last check changed the record to the new IP.</summary>
    Updated,
    /// <summary>The public IP couldn't be determined (offline, services disagree): nothing was changed.</summary>
    NoIp,
    /// <summary>Cloudflare refused or couldn't be reached, or the record is gone.</summary>
    Error,
}

/// <summary>A read-only snapshot of one dynamic-DNS job, for the UI.</summary>
public sealed class DdnsJobInfo
{
    public string Id { get; init; } = string.Empty;
    /// <summary>The Echoes account it uses (its name when added / last synced).</summary>
    public string Account { get; init; } = string.Empty;
    /// <summary>Fingerprint of the account's credentials (<see cref="DdnsService.AccountKeyOf"/>), not a secret.</summary>
    public string AccountKey { get; init; } = string.Empty;
    public string ZoneId { get; init; } = string.Empty;
    public string ZoneName { get; init; } = string.Empty;
    public string RecordId { get; init; } = string.Empty;
    public string RecordName { get; init; } = string.Empty;
    /// <summary>A or AAAA.</summary>
    public string Type { get; init; } = "A";
    /// <summary>What the record held when last seen ("" = not read yet).</summary>
    public string RecordIp { get; init; } = string.Empty;
    /// <summary>What it held before the last change ("" = never changed here).</summary>
    public string PreviousIp { get; init; } = string.Empty;
    public DateTimeOffset? LastCheck { get; init; }
    public DateTimeOffset? LastChange { get; init; }
    public DateTimeOffset? NextAttempt { get; init; }
    public DdnsState State { get; init; }
    /// <summary>The outcome in words (an error says why, without secrets).</summary>
    public string Message { get; init; } = string.Empty;
    public int Failures { get; init; }
    /// <summary>A check of this job is running.</summary>
    public bool Busy { get; init; }
    /// <summary>The saved credentials don't open on this device (restored from another one): the account must be
    /// opened once in Echoes to resume.</summary>
    public bool NeedsAccount { get; init; }
}

/// <summary>The last public-IP lookup of one family.</summary>
public sealed class DdnsPublicIp
{
    public DdnsFamily Family { get; init; }
    public string? Address { get; init; }
    public string Error { get; init; } = string.Empty;
    public DateTimeOffset At { get; init; }
}

/// <summary>
/// Dynamic DNS for Cloudflare: keeps chosen A / AAAA records on this device's public IP. Runs while Echoes runs — the
/// desktop tray included — every <see cref="Interval"/>, right away at start and shortly after a network change.
///
/// <para>It must work after a restart WITHOUT the master password (the vault stays locked), so each job keeps its own
/// copy of only what the update needs: the account's API token (or Global API key + email) and proxy settings — sealed
/// with <see cref="SecretProtector"/> (the per-install device key, "enc2:") — plus the zone and record ids and names.
/// The whole job list is sealed once more as the "ddns.jobs" profile setting; nothing of it is stored as plain text.
/// Removing a job, or the account it uses, deletes that copy.</para>
///
/// <para>The public IP is asked directly (never through the account's proxy) and cross-checked between independent
/// services (<see cref="DdnsIpDetector"/>); a record is written only when they agree and the record differs. The API
/// calls go through the account's proxy, like everything else the account does. Failures back off (a refused token or a
/// missing permission much longer than a network error).</para>
/// </summary>
public sealed class DdnsService
{
    public const string SettingKey = "ddns.jobs";
    public const int MaxJobs = 50;
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
    // An unchanged IP whose record was confirmed this recently isn't read again (one GET per job per hour, so an edit
    // made elsewhere — the dashboard, another tool — is still noticed and corrected).
    private static readonly TimeSpan VerifyEvery = TimeSpan.FromHours(1);
    private static readonly TimeSpan NetworkSettle = TimeSpan.FromSeconds(15);

    private static readonly Lazy<DdnsService> _instance = new(() => new DdnsService(), LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>The app's one service (created on first use; loads the jobs lazily, off the UI thread when started by
    /// <see cref="Start"/>).</summary>
    public static DdnsService Instance => _instance.Value;

    /// <summary>
    /// Start the background updater (call once at app start; later calls do nothing). Returns at once: loading the jobs
    /// and the first check run on the thread pool. Never throws.
    /// </summary>
    public static void Start()
    {
        if (SuppressStart) return;
        try { Instance.StartLoop(); }
        catch (Exception ex) { CrashLog.Write("Ddns.Start", ex); }
    }

    /// <summary>Test hook: <see cref="Start"/> does nothing (a harness runs the checks itself).</summary>
    internal static bool SuppressStart { get; set; }

    private sealed class Job
    {
        public string Id = string.Empty, Account = string.Empty, AccountKey = string.Empty;
        public string ZoneId = string.Empty, ZoneName = string.Empty, RecordId = string.Empty, RecordName = string.Empty, Type = "A";
        public string Cred = string.Empty;   // the sealed credentials JSON: opened only for the API call that needs it
        public string RecordIp = string.Empty, PreviousIp = string.Empty;
        public long Verified, Checked, Changed, Next;   // unix seconds, 0 = never / now
        public DdnsState State = DdnsState.Pending;
        public string Message = string.Empty;
        public int Failures;
        public bool Busy, NeedsAccount;
        public DdnsFamily Family => Type == "AAAA" ? DdnsFamily.V6 : DdnsFamily.V4;
    }

    private readonly object _gate = new();
    private readonly List<Job> _jobs = new();
    private bool _loaded;
    private bool _unreadable;          // sealed with a key this run can't load: never written over (a later run may open it)
    private bool _dirty;               // a check changed something worth keeping (not just "checked at")
    private DdnsPublicIp? _lastV4, _lastV6;
    private CancellationTokenSource? _loopCts;
    private readonly SemaphoreSlim _wake = new(0, 1);
    private int _networkPending;

    /// <summary>Raised (on any thread) after the jobs or their states changed.</summary>
    public event Action? Changed;

    /// <summary>A fresh service over the stored jobs. The app uses <see cref="Instance"/>; a test creates one to stand
    /// for "Echoes restarted".</summary>
    internal DdnsService()
    {
        MasterSession.RestoreApplied += OnRestoreApplied;
    }

    // ================================================================ credentials

    /// <summary>What a job needs to call the API: one sign-in method and the account's proxy. Never printed.</summary>
    public sealed class Credentials
    {
        public Credentials(bool useToken, string? token, string? email, string? key, string? proxy, string? proxyUser, string? proxyPass)
        {
            UseToken = useToken;
            // only the sign-in method in use is kept
            Token = useToken ? (token ?? string.Empty).Trim() : string.Empty;
            Email = useToken ? string.Empty : (email ?? string.Empty).Trim();
            Key = useToken ? string.Empty : (key ?? string.Empty).Trim();
            Proxy = (proxy ?? string.Empty).Trim();
            ProxyUser = Proxy.Length > 0 ? proxyUser ?? string.Empty : string.Empty;
            ProxyPass = Proxy.Length > 0 ? proxyPass ?? string.Empty : string.Empty;
        }

        public bool UseToken { get; }
        public string Token { get; }
        public string Email { get; }
        public string Key { get; }
        public string Proxy { get; }
        public string ProxyUser { get; }
        public string ProxyPass { get; }

        public bool IsUsable => UseToken ? Token.Length > 0 : Email.Length > 0 && Key.Length > 0;
        public string AccountKey => AccountKeyOf(UseToken, Token, Email, Key);

        internal bool SameAs(Credentials o)
            => UseToken == o.UseToken && Token == o.Token && Email == o.Email && Key == o.Key
               && Proxy == o.Proxy && ProxyUser == o.ProxyUser && ProxyPass == o.ProxyPass;

        internal string Seal() => SecretProtector.Protect(new JsonObject
        {
            ["useToken"] = UseToken,
            ["token"] = Token,
            ["email"] = Email,
            ["key"] = Key,
            ["proxy"] = Proxy,
            ["proxyUser"] = ProxyUser,
            ["proxyPass"] = ProxyPass,
        }.ToJsonString());

        internal static Credentials? Open(string sealedJson)
        {
            if (string.IsNullOrEmpty(sealedJson) || !SecretProtector.IsProtected(sealedJson)) return null;
            // The legacy "enc1:" seal is derived from the machine and user NAMES: anyone who knows them can make one that
            // opens here, e.g. inside an imported backup, and such a job would then write this device's public IP into
            // their record. Here it is only ever written when the run had no device key, so with the key it is refused:
            // the job waits for its account (the vault's next unlock re-seals it with the device key, UpdateAccount).
            if (SecretProtector.IsLegacy(sealedJson) && SecretProtector.IsKeyAvailable) return null;
            string json = SecretProtector.Unprotect(sealedJson);
            if (json.Length == 0) return null;
            try
            {
                if (JsonNode.Parse(json) is not JsonObject o) return null;
                var c = new Credentials(CfJson.Bool(o["useToken"]), CfJson.Str(o["token"]), CfJson.Str(o["email"]), CfJson.Str(o["key"]),
                                        CfJson.Str(o["proxy"]), CfJson.Str(o["proxyUser"]), CfJson.Str(o["proxyPass"]));
                return c.IsUsable ? c : null;
            }
            catch (JsonException) { return null; }
        }

        internal CloudflareApi CreateApi()
            => CloudflareApi.Create(UseToken, Token, Email, Key,
                                    Proxy.Length > 0 ? Proxy : null, Proxy.Length > 0 ? ProxyUser : null, Proxy.Length > 0 ? ProxyPass : null);

        public override string ToString() => "(credentials)";
    }

    /// <summary>
    /// A stable fingerprint of an account's sign-in (HMAC-SHA256 of the method + token, or email + key, under a fixed
    /// app label; 16 bytes hex). It links a job to its account in the vault — to follow a changed token or proxy, and to
    /// drop the job with the account — and reveals nothing usable: tokens and keys are long random strings.
    /// </summary>
    public static string AccountKeyOf(bool useToken, string? token, string? email, string? key)
    {
        string id = useToken
            ? "t|" + (token ?? string.Empty).Trim()
            : "k|" + (email ?? string.Empty).Trim().ToLowerInvariant() + "|" + (key ?? string.Empty).Trim();
        byte[] mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes("Echoes.DDNS.account.v1"), Encoding.UTF8.GetBytes(id));
        return Convert.ToHexString(mac, 0, 16).ToLowerInvariant();
    }

    // ================================================================ reading

    /// <summary>A snapshot of every job, in record-name order.</summary>
    public IReadOnlyList<DdnsJobInfo> Jobs
    {
        get
        {
            EnsureLoaded();
            lock (_gate)
                return _jobs.OrderBy(j => j.RecordName, StringComparer.OrdinalIgnoreCase).ThenBy(j => j.Type, StringComparer.Ordinal)
                            .Select(Info).ToList();
        }
    }

    /// <summary>The saved jobs exist but can't be opened in this run (the device key is unavailable).</summary>
    public bool IsUnreadable
    {
        get { lock (_gate) return _unreadable; }
    }

    public DdnsPublicIp? LastIpv4
    {
        get { lock (_gate) return _lastV4; }
    }

    public DdnsPublicIp? LastIpv6
    {
        get { lock (_gate) return _lastV6; }
    }

    /// <summary>True when (<paramref name="zoneId"/>, <paramref name="recordId"/>) is kept updated.</summary>
    public bool Has(string zoneId, string recordId)
    {
        EnsureLoaded();
        lock (_gate) return Find(zoneId, recordId) != null;
    }

    private static DdnsJobInfo Info(Job j) => new()
    {
        Id = j.Id,
        Account = j.Account,
        AccountKey = j.AccountKey,
        ZoneId = j.ZoneId,
        ZoneName = j.ZoneName,
        RecordId = j.RecordId,
        RecordName = j.RecordName,
        Type = j.Type,
        RecordIp = j.RecordIp,
        PreviousIp = j.PreviousIp,
        LastCheck = Time(j.Checked),
        LastChange = Time(j.Changed),
        NextAttempt = j.Next > 0 ? DateTimeOffset.FromUnixTimeSeconds(j.Next) : null,
        State = j.State,
        Message = j.Message,
        Failures = j.Failures,
        Busy = j.Busy,
        NeedsAccount = j.NeedsAccount,
    };

    private static DateTimeOffset? Time(long unix) => unix > 0 ? DateTimeOffset.FromUnixTimeSeconds(unix) : null;
    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private Job? Find(string zoneId, string recordId)
        => _jobs.FirstOrDefault(j => string.Equals(j.ZoneId, zoneId, StringComparison.OrdinalIgnoreCase)
                                     && string.Equals(j.RecordId, recordId, StringComparison.OrdinalIgnoreCase));

    // ================================================================ changing

    /// <summary>
    /// Keep a record updated with this device's public IP. Returns null when added (or already there: its account is
    /// refreshed), else a readable reason. The first check runs right away.
    /// </summary>
    public string? Add(Credentials cred, string accountName, string zoneId, string zoneName, string recordId, string recordName,
                       string type, string? currentContent = null)
    {
        if (!cred.IsUsable) return "This account has no API token or key.";
        if (!CloudflareApi.IsId(zoneId) || !CloudflareApi.IsId(recordId)) return "This record can't be kept updated (unknown zone or record id).";
        type = (type ?? string.Empty).ToUpperInvariant();
        if (type is not ("A" or "AAAA")) return "Only A and AAAA records can follow your public IP.";
        EnsureLoaded();
        lock (_gate)
        {
            if (_unreadable) return "Your saved dynamic DNS records can't be read right now (the device key is unavailable). Restart Echoes and try again.";
            var job = Find(zoneId, recordId);
            if (job is null)
            {
                if (_jobs.Count >= MaxJobs) return $"At most {MaxJobs} records can be kept updated.";
                job = new Job
                {
                    Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
                    ZoneId = zoneId.ToLowerInvariant(),
                    RecordId = recordId.ToLowerInvariant(),
                    Type = type,
                    RecordIp = DdnsIpDetector.Canonical(currentContent) ?? string.Empty,
                };
                _jobs.Add(job);
            }
            job.Account = Clip(accountName, 60);
            job.AccountKey = cred.AccountKey;
            job.ZoneName = Clip(zoneName, 253);
            job.RecordName = Clip(recordName, 253);
            job.Cred = cred.Seal();
            job.NeedsAccount = false;
            job.State = DdnsState.Pending;
            job.Message = "Checking…";
            job.Failures = 0;
            job.Verified = 0;
            job.Next = 0;   // due now
            SaveLocked();
        }
        Raise();
        Wake();
        return null;
    }

    /// <summary>Stop keeping a job's record updated; its saved credentials go with it.</summary>
    public bool Remove(string jobId)
    {
        EnsureLoaded();
        bool removed;
        lock (_gate)
        {
            removed = _jobs.RemoveAll(j => j.Id == jobId) > 0;
            if (removed) SaveLocked();
        }
        if (removed) Raise();
        return removed;
    }

    /// <summary>Stop keeping (<paramref name="zoneId"/>, <paramref name="recordId"/>) updated.</summary>
    public bool RemoveRecord(string zoneId, string recordId)
    {
        EnsureLoaded();
        string? id;
        lock (_gate) id = Find(zoneId, recordId)?.Id;
        return id != null && Remove(id);
    }

    /// <summary>The account was removed from Echoes: every job using it goes, with its saved credentials.</summary>
    public int RemoveAccount(string accountKey)
    {
        if (string.IsNullOrEmpty(accountKey)) return 0;
        EnsureLoaded();
        int n;
        lock (_gate)
        {
            n = _jobs.RemoveAll(j => j.AccountKey == accountKey);
            if (n > 0) SaveLocked();
        }
        if (n > 0) Raise();
        return n;
    }

    /// <summary>
    /// The account (known by <paramref name="oldKey"/>) was edited, or the vault was opened: its jobs take its current
    /// credentials, proxy and name. A job whose saved copy differs (a new token, a proxy change, a copy this device can't
    /// open) is re-sealed and checked again soon. Returns how many jobs changed.
    /// </summary>
    public int UpdateAccount(string oldKey, Credentials cred, string accountName)
    {
        if (string.IsNullOrEmpty(oldKey) || !cred.IsUsable) return 0;
        EnsureLoaded();
        int changed = 0;
        bool recheck = false;
        lock (_gate)
        {
            if (_unreadable) return 0;
            string newKey = cred.AccountKey;
            string name = Clip(accountName, 60);
            foreach (var j in _jobs.Where(j => j.AccountKey == oldKey))
            {
                bool any = false;
                var current = Credentials.Open(j.Cred);
                if (current is null || !current.SameAs(cred))
                {
                    j.Cred = cred.Seal();
                    j.AccountKey = newKey;
                    j.NeedsAccount = false;
                    if (j.State is DdnsState.Error or DdnsState.Pending || j.Failures > 0)
                    {
                        j.Failures = 0;
                        j.Next = 0;
                        recheck = true;
                    }
                    any = true;
                }
                if (j.Account != name) { j.Account = name; any = true; }
                if (any) changed++;
            }
            if (changed > 0) SaveLocked();
        }
        if (changed > 0) Raise();
        if (recheck) Wake();
        return changed;
    }

    /// <summary>Check every job now (the panel's "Check now").</summary>
    public void CheckNow()
    {
        EnsureLoaded();
        lock (_gate)
            foreach (var j in _jobs) j.Next = 0;
        Wake();
    }

    private static string Clip(string? s, int max)
    {
        s = (s ?? string.Empty).Trim();
        return s.Length > max ? s[..max] : s;
    }

    // ================================================================ storage

    private void EnsureLoaded()
    {
        lock (_gate)
        {
            if (_loaded) return;
            _unreadable = false;
            string stored = ProfileService.Instance.GetSetting(SettingKey) ?? string.Empty;
            if (stored.Length == 0) { _loaded = true; return; }
            string json = SecretProtector.Unprotect(stored);
            if (json.Length == 0)
            {
                // No device key this run: leave the stored jobs untouched (and refuse changes) — a later run may open them.
                if (!SecretProtector.IsKeyAvailable) { _unreadable = true; return; }
                // Sealed with another install's key (or damaged): it can never open here.
                ProfileService.Instance.Remove(SettingKey);
                _loaded = true;
                return;
            }
            _jobs.Clear();
            try
            {
                if (JsonNode.Parse(json) is JsonArray arr)
                    foreach (var n in arr)
                        if (n is JsonObject o && Parse(o) is { } job && Find(job.ZoneId, job.RecordId) is null && _jobs.Count < MaxJobs)
                            _jobs.Add(job);
            }
            catch (JsonException) { _jobs.Clear(); }
            _loaded = true;
        }
    }

    private static Job? Parse(JsonObject o)
    {
        string zone = CfJson.Str(o["zone"]), rec = CfJson.Str(o["rec"]), type = CfJson.Str(o["type"]);
        if (!CloudflareApi.IsId(zone) || !CloudflareApi.IsId(rec) || type is not ("A" or "AAAA")) return null;
        string id = CfJson.Str(o["id"]);
        var job = new Job
        {
            Id = id.Length is > 0 and <= 32 ? id : Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(),
            Account = Clip(CfJson.Str(o["acct"]), 60),
            AccountKey = CfJson.Str(o["acctKey"]),
            ZoneId = zone.ToLowerInvariant(),
            ZoneName = Clip(CfJson.Str(o["zoneName"]), 253),
            RecordId = rec.ToLowerInvariant(),
            RecordName = Clip(CfJson.Str(o["name"]), 253),
            Type = type,
            Cred = CfJson.Str(o["cred"]),
            RecordIp = DdnsIpDetector.Canonical(CfJson.Str(o["ip"])) ?? string.Empty,
            PreviousIp = DdnsIpDetector.Canonical(CfJson.Str(o["prev"])) ?? string.Empty,
            Verified = CfJson.Long(o["verified"]) ?? 0,
            Checked = CfJson.Long(o["checked"]) ?? 0,
            Changed = CfJson.Long(o["changed"]) ?? 0,
            Failures = Math.Clamp(CfJson.Int(o["fails"]) ?? 0, 0, 100),
            Message = Clip(CfJson.Str(o["msg"]), 600),
            State = CfJson.Str(o["state"]) switch
            {
                "ok" => DdnsState.UpToDate,
                "updated" => DdnsState.Updated,
                "noip" => DdnsState.NoIp,
                "error" => DdnsState.Error,
                _ => DdnsState.Pending,
            },
            Next = 0,   // a (re)start checks everything right away
        };
        return job;
    }

    // Under _gate. Everything goes into ONE sealed value: no plain field of a job is in the profile file.
    private void SaveLocked()
    {
        if (!_loaded || _unreadable) return;
        _dirty = false;
        if (_jobs.Count == 0)
        {
            ProfileService.Instance.Remove(SettingKey);
            return;
        }
        var arr = new JsonArray();
        foreach (var j in _jobs)
            arr.Add((JsonNode)new JsonObject
            {
                ["id"] = j.Id,
                ["acct"] = j.Account,
                ["acctKey"] = j.AccountKey,
                ["zone"] = j.ZoneId,
                ["zoneName"] = j.ZoneName,
                ["rec"] = j.RecordId,
                ["name"] = j.RecordName,
                ["type"] = j.Type,
                ["cred"] = j.Cred,
                ["ip"] = j.RecordIp,
                ["prev"] = j.PreviousIp,
                ["verified"] = j.Verified,
                ["checked"] = j.Checked,
                ["changed"] = j.Changed,
                ["fails"] = j.Failures,
                ["msg"] = j.Message,
                ["state"] = j.State switch
                {
                    DdnsState.UpToDate => "ok",
                    DdnsState.Updated => "updated",
                    DdnsState.NoIp => "noip",
                    DdnsState.Error => "error",
                    _ => "pending",
                },
            });
        ProfileService.Instance.SetSetting(SettingKey, SecretProtector.Protect(arr.ToJsonString()));
    }

    // A backup restore replaced the profile: read the jobs again from it (nothing in memory is written back).
    private void OnRestoreApplied() => Reload();

    /// <summary>Forget the in-memory jobs and read them again from the profile on next use.</summary>
    internal void Reload()
    {
        lock (_gate)
        {
            _loaded = false;
            _jobs.Clear();
        }
        Raise();
        Wake();
    }

    private void Raise()
    {
        try { Changed?.Invoke(); }
        catch (Exception ex) { CrashLog.Write("Ddns.Changed", ex); }
    }

    // ================================================================ the loop

    internal void StartLoop()
    {
        CancellationTokenSource cts;
        lock (_gate)
        {
            if (_loopCts != null) return;
            cts = _loopCts = new CancellationTokenSource();
        }
        try { NetworkChange.NetworkAddressChanged += OnNetworkChanged; }
        catch { /* not available on this platform: the 5-minute checks still run */ }
        _ = Task.Run(() => LoopAsync(cts.Token));
    }

    /// <summary>Stop the background loop (tests; a stopped service can be started again).</summary>
    internal void Stop()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _loopCts;
            _loopCts = null;
        }
        if (cts is null) return;
        try { NetworkChange.NetworkAddressChanged -= OnNetworkChanged; } catch { }
        cts.Cancel();
    }

    internal bool IsRunning
    {
        get { lock (_gate) return _loopCts != null; }
    }

    private void Wake()
    {
        try { if (_wake.CurrentCount == 0) _wake.Release(); }
        catch (SemaphoreFullException) { }
    }

    // A new network (Wi-Fi switch, VPN, a reconnect) often means a new public IP: check soon, once it has settled.
    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        if (Interlocked.Exchange(ref _networkPending, 1) == 1) return;
        _ = Task.Delay(NetworkSettle).ContinueWith(_ =>
        {
            Volatile.Write(ref _networkPending, 0);
            bool any;
            lock (_gate)
            {
                any = _jobs.Count > 0;
                foreach (var j in _jobs)
                    if (j.State != DdnsState.Error) j.Next = 0;   // a refused token doesn't get better with a new network
            }
            if (any) Wake();
        }, TaskScheduler.Default);
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TimeSpan wait;
            try { wait = await RunDueAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                CrashLog.Write("Ddns.Loop", ex);
                wait = Interval;
            }
            try { await _wake.WaitAsync(wait, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>
    /// One pass: every due job (all of them with <paramref name="force"/>) is checked. Returns how long until the next
    /// job is due. The loop calls it; a test calls it directly.
    /// </summary>
    internal async Task<TimeSpan> RunDueAsync(CancellationToken ct, bool force = false)
    {
        EnsureLoaded();
        long now = Now;
        List<Job> due;
        lock (_gate)
        {
            due = _jobs.Where(j => force || j.Next <= now).ToList();
            foreach (var j in due) j.Busy = true;
        }
        if (due.Count == 0) return NextWait();
        Raise();

        var families = due.Select(j => j.Family).Distinct().ToList();
        var lookups = families.Select(f => DdnsIpDetector.DetectAsync(f, ct)).ToList();
        var results = new Dictionary<DdnsFamily, DdnsIpResult>();
        try
        {
            for (int i = 0; i < families.Count; i++)
            {
                var r = await lookups[i].ConfigureAwait(false);
                results[families[i]] = r;
                var ipState = new DdnsPublicIp { Family = families[i], Address = r.Address, Error = r.Error, At = DateTimeOffset.UtcNow };
                lock (_gate)
                {
                    if (families[i] == DdnsFamily.V4) _lastV4 = ipState;
                    else _lastV6 = ipState;
                }
            }

            foreach (var job in due)
            {
                ct.ThrowIfCancellationRequested();
                try { await CheckJobAsync(job, results[job.Family], ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    CrashLog.Write("Ddns.Check", ex);
                    Finish(job, DdnsState.Error, "Unexpected error: " + ex.Message, Backoff.Network);
                }
            }
        }
        finally
        {
            lock (_gate)
            {
                foreach (var j in due) j.Busy = false;
                if (_dirty) SaveLocked();   // a plain "still the same" check writes nothing
            }
            Raise();
        }
        return NextWait();
    }

    private TimeSpan NextWait()
    {
        lock (_gate)
        {
            if (_jobs.Count == 0) return Interval;
            long next = _jobs.Min(j => j.Next);
            long secs = Math.Clamp(next - Now, 5, (long)Interval.TotalSeconds);
            return TimeSpan.FromSeconds(secs);
        }
    }

    private enum Backoff { None, Detect, Network, Refused }

    private async Task CheckJobAsync(Job job, DdnsIpResult ip, CancellationToken ct)
    {
        if (!ip.Ok)
        {
            Finish(job, DdnsState.NoIp, ip.Error + " The record was left as it is.", Backoff.Detect);
            return;
        }
        string address = ip.Address!;
        string cred, zoneId, recordId;
        bool fresh;
        lock (_gate)
        {
            if (!_jobs.Contains(job)) return;   // removed meanwhile
            cred = job.Cred;
            zoneId = job.ZoneId;
            recordId = job.RecordId;
            fresh = job.RecordIp == address && job.Verified > Now - (long)VerifyEvery.TotalSeconds;
        }
        if (fresh)
        {
            Finish(job, DdnsState.UpToDate, $"Up to date ({address}).", Backoff.None, recordIp: address, verified: false);
            return;
        }

        var creds = Credentials.Open(cred);
        if (creds is null)
        {
            lock (_gate) job.NeedsAccount = true;
            Finish(job, DdnsState.Error,
                   "Its saved token can't be opened on this device. Unlock Cloudflare in Echoes once (with this account in it) to resume.",
                   Backoff.Refused);
            return;
        }

        CloudflareApi api;
        try { api = creds.CreateApi(); }
        catch (ArgumentException ex)
        {
            Finish(job, DdnsState.Error, ex.Message, Backoff.Refused);
            return;
        }
        using (api)
        {
            string path = CloudflareApi.RecordPath(zoneId, recordId);
            var read = await api.GetAsync(path, CfPermission.DnsEdit, ct).ConfigureAwait(false);
            if (!read.Success)
            {
                FinishApiError(job, read, "read");
                return;
            }
            string type = CfJson.Str(read.Result?["type"]).ToUpperInvariant();
            if (type != job.Type)
            {
                Finish(job, DdnsState.Error, $"The record isn't an {job.Type} record any more ({type}). Remove it here.", Backoff.Refused);
                return;
            }
            string currentRaw = CfJson.Str(read.Result?["content"]);
            string? current = DdnsIpDetector.Canonical(currentRaw);
            if (current == address)
            {
                Finish(job, DdnsState.UpToDate, $"Up to date ({address}).", Backoff.None, recordIp: address, verified: true);
                return;
            }

            // Removed (or a restore replaced the jobs) while the record was being read: that record is no longer ours to
            // change. Checked right before the write, under the lock Remove / Reload take.
            lock (_gate)
                if (!_jobs.Contains(job)) return;
            var write = await api.PatchAsync(path, new JsonObject { ["content"] = address }, CfPermission.DnsEdit, ct).ConfigureAwait(false);
            if (!write.Success)
            {
                FinishApiError(job, write, "update");
                return;
            }
            string old = current ?? currentRaw;
            Finish(job, DdnsState.Updated, old.Length > 0 ? $"Changed from {old} to {address}." : $"Set to {address}.",
                   Backoff.None, recordIp: address, verified: true, previous: old);
        }
    }

    private void FinishApiError(Job job, CfResponse r, string what)
    {
        string zone;
        lock (_gate) zone = job.ZoneName.Length > 0 ? job.ZoneName : "its zone";
        if (r.Status == 404 || r.Codes.Contains(81044))
        {
            Finish(job, DdnsState.Error, $"The record no longer exists in {zone}. Remove it here, or turn it on again for the new record.", Backoff.Refused);
            return;
        }
        if (r.AuthFailed)
        {
            Finish(job, DdnsState.Error, $"Cloudflare refused to {what} the record: {r.Error}", Backoff.Refused);
            return;
        }
        string text = r.Error.StartsWith("Couldn't reach Cloudflare", StringComparison.Ordinal) || r.Error.StartsWith("Cloudflare", StringComparison.Ordinal)
            ? r.Error
            : $"Couldn't {what} the record: {r.Error}";
        Finish(job, DdnsState.Error, text, Backoff.Network);
    }

    // Record the outcome of a check and schedule the next one. Backoff after repeated failures: an unknown public IP
    // 5 → 10 → 15 min; a network / API error 5 → 10 → 20 → 40 → 60 min; a refusal (token, permission, gone record)
    // 30 min → 1 h → 2 h … 6 h.
    private void Finish(Job job, DdnsState state, string message, Backoff backoff,
                        string? recordIp = null, bool verified = false, string? previous = null)
    {
        lock (_gate)
        {
            if (!_jobs.Contains(job)) return;
            long now = Now;
            string text = Clip(message, 600);
            // worth writing: a new state or message, a new address, a change, an hourly confirmation (not "checked at")
            if (job.State != state || job.Message != text || (recordIp != null && recordIp != job.RecordIp) || verified || previous != null)
                _dirty = true;
            job.Checked = now;
            job.State = state;
            job.Message = text;
            if (recordIp != null) job.RecordIp = recordIp;
            if (verified) job.Verified = now;
            if (previous != null)
            {
                job.PreviousIp = previous;
                job.Changed = now;
            }
            if (backoff == Backoff.None)
            {
                job.Failures = 0;
                job.NeedsAccount = false;
                job.Next = now + (long)Interval.TotalSeconds;
                return;
            }
            job.Failures = Math.Min(job.Failures + 1, 100);
            int n = job.Failures;
            double minutes = backoff switch
            {
                Backoff.Detect => 5 * Math.Min(n, 3),
                Backoff.Network => Math.Min(5 * Math.Pow(2, Math.Min(n - 1, 6)), 60),
                _ => Math.Min(30 * Math.Pow(2, Math.Min(n - 1, 6)), 360),
            };
            job.Next = now + (long)(minutes * 60);
        }
    }
}
