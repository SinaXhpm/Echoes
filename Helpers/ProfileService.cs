using System;
using System.Globalization;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.Helpers;

/// <summary>
/// Single source of truth for all app settings/state, persisted to ONE profile file
/// (echoes.profile.json in the user data dir). Holds input history, simple settings
/// (DNS servers, Cloudflare credentials, ...), and SSH known-host pins.
/// Encrypted notes (notes.dat) stay separate by design.
///
/// <para>Writes are behind and coalesced: a change marks the profile dirty and one background write a moment later
/// persists everything (a burst like SetMany + Remove×9 is one write, and none of it runs on the UI thread).
/// <see cref="Flush"/> writes synchronously — MainViewModel.FlushPersistence (exit / backgrounded), process exit, a
/// backup export and a TOFU host pin call it. Every write is atomic (temp file + fsync + rename).</para>
/// </summary>
public sealed class ProfileService
{
    public static ProfileService Instance { get; } = new();

    private const int MaxPerKey = 50;
    // Longest input kept in history. The scanner / monitor boxes take whole pasted lists, and each entry is part of the
    // one profile file every change rewrites: a single 100 KB paste (kept up to 50 times) grew it to megabytes.
    public const int MaxEntryChars = 4096;
    private const int WriteDelayMs = 250;

    private readonly string _path = AppStorage.UserPath("echoes.profile.json");
    private readonly object _gate = new();        // guards the stores and the counters below
    private readonly object _writeGate = new();   // serializes file writes; taken BEFORE _gate, never while holding it

    private readonly Dictionary<string, ObservableCollection<string>> _history = new();
    private readonly Dictionary<string, string> _settings = new();
    private readonly Dictionary<string, string> _knownHosts = new();

    private long _version;                  // in-memory change count (under _gate)
    private long _savedVersion;             // the count last written to disk (under _writeGate)
    private bool _unreadable;               // the file on disk failed to load: set aside before the first write (under _writeGate)
    private bool _writeScheduled;
    private long _historyVersion;            // bumped on every history change: HistoryViewModel skips no-op rebuilds

    private ProfileService()
    {
        Load();
        // Desktop: a change made during shutdown, after the app's own flush, still reaches the disk.
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Flush();
        // Off the UI thread: load SecretProtector's key and upgrade legacy "enc1:" values (see MigrateLegacySecrets).
        _ = Task.Run(BackgroundInit);
    }

    // ---------- Input history ----------
    // Assumes _gate is already held.
    private ObservableCollection<string> GetHistoryLocked(string key)
    {
        if (!_history.TryGetValue(key, out var list))
        {
            list = new ObservableCollection<string>();
            _history[key] = list;
        }
        return list;
    }

    public ObservableCollection<string> GetHistory(string key)
    {
        lock (_gate) { return GetHistoryLocked(key); }
    }

    public string? LastHistory(string key)
    {
        lock (_gate)
        {
            var list = GetHistoryLocked(key);
            return list.Count > 0 ? list[0] : null;
        }
    }

    public void AddHistory(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        value = value.Trim();
        if (value.Length > MaxEntryChars) return;   // a whole pasted list isn't worth re-writing on every save
        value = Sanitize(value);
        if (value.Length == 0) return;   // it was nothing but credentials

        lock (_gate)
        {
            var list = GetHistoryLocked(key);
            int existing = -1;
            for (int i = 0; i < list.Count; i++)
                if (string.Equals(list[i], value, StringComparison.Ordinal)) { existing = i; break; }

            if (existing == 0) return;
            if (existing > 0) list.RemoveAt(existing);
            list.Insert(0, value);
            while (list.Count > MaxPerKey) list.RemoveAt(list.Count - 1);

            _historyVersion++;
            Save();
        }
    }

    /// <summary>Changes whenever any history list changes (add, clear, restore).</summary>
    public long HistoryVersion
    {
        get { lock (_gate) return _historyVersion; }
    }

    // Snapshot of every non-empty history list (key → values), for the History tab.
    public IReadOnlyList<(string Key, IReadOnlyList<string> Values)> AllHistory()
    {
        lock (_gate)
            return _history
                .Where(kv => kv.Value.Count > 0)
                .Select(kv => (kv.Key, (IReadOnlyList<string>)kv.Value.ToList()))
                .ToList();
    }

    // Wipe all input history (empties the live UI-bound lists too), then persist.
    public void ClearAllHistory()
    {
        lock (_gate)
        {
            foreach (var list in _history.Values) list.Clear();
            _historyVersion++;
            Save();
        }
    }

    // Strip credentials before persisting (the history is plaintext, and listed on the DATA tab):
    //  • a URL's user:password@ — everything up to the LAST '@' of the authority, so a password holding an '@' goes
    //    whole; an '@' after the host (path / ?query / #fragment) is not user-info and stays;
    //  • a scheme-less user:password@host:port, as typed into the IP Info / Check-Host proxy boxes ("user:pass@1.2.3.4:8080"
    //    parses as a proxy) — at the start of the value or of any line / word of a pasted list. Only with a ':' before
    //    the '@', so "admin@example.com" or "git@host" stay as typed.
    //  • secret-looking query values and a Telegram bot token in a URL's path (UrlSecrets).
    private static string Sanitize(string value)
        => UrlSecrets.Redact(value.IndexOf('@') < 0
            ? value
            : Credentials.BareUserInfo.Replace(Credentials.UrlUserInfo.Replace(value, "$1"), "$1"));

    // A holder class, NOT static fields of ProfileService: Instance (the first static initializer) runs the constructor,
    // whose Load() already sanitizes, before any static field declared below it is set — a null Regex there made every
    // profile "unreadable". A nested class is initialized on its first use, whatever the order.
    private static class Credentials
    {
        public static readonly Regex UrlUserInfo = new(@"(://)[^/?#\s]*@", RegexOptions.CultureInvariant);
        public static readonly Regex BareUserInfo = new(@"(^|\s)(?!mailto:)[^\s/?#@:]+:[^\s/?#]*@",
                                                        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    }

    // ---------- Simple settings ----------
    // Every accessor holds _gate: mutators can run off the UI thread (SSH TOFU pin on a
    // background thread, debounced persistence), racing the background write's enumeration of the stores.
    public string? GetSetting(string key)
    {
        lock (_gate) { return _settings.TryGetValue(key, out var v) ? v : null; }
    }
    public void SetSetting(string key, string? value)
    {
        lock (_gate) { _settings[key] = value ?? string.Empty; Save(); }
    }
    public void Remove(string key)
    {
        lock (_gate) { if (_settings.Remove(key)) Save(); }
    }
    public bool GetBool(string key, bool def = false)
    {
        lock (_gate) { return _settings.TryGetValue(key, out var v) && bool.TryParse(v, out var b) ? b : def; }
    }
    public void SetBool(string key, bool value) => SetSetting(key, value ? "true" : "false");
    public int GetInt(string key, int def = 0)
    {
        lock (_gate) { return _settings.TryGetValue(key, out var v) && int.TryParse(v, out var i) ? i : def; }
    }

    // Set several settings and write the file once (avoids one write per field).
    public void SetMany(params (string key, string? value)[] items)
    {
        lock (_gate)
        {
            foreach (var (k, v) in items) _settings[k] = v ?? string.Empty;
            Save();
        }
    }

    // ---------- SSH known hosts (trust-on-first-use pins) ----------
    public string? GetKnownHost(string host)
    {
        lock (_gate) { return _knownHosts.TryGetValue(host, out var v) ? v : null; }
    }
    public void SetKnownHost(string host, string fingerprint)
    {
        lock (_gate) { _knownHosts[host] = fingerprint; Save(); }
        Flush();   // a trust anchor: on disk before the connection proceeds (called on SSH.NET's thread, not the UI's)
    }

    // ---------- Backup import ----------
    // Settings that route traffic through a third party or weaken TLS / host-key checks. A backup may come from someone
    // else ("team settings" + its password): with a planted SSH host pin, ssh.inEnabled + an attacker SOCKS host would
    // silently man-in-the-middle the SSH password; curl.useProxy + curl.skipSsl likewise; ssh.outEnabled opens a local
    // SOCKS listener on whatever address the backup names. An import therefore never switches them on. The monitor's
    // Telegram alerts likewise: with the backup's bot token and chat they would send every monitored host's ups and downs
    // to whoever made the backup (the token and chat themselves are kept — one switch turns them back on).
    private static readonly string[] RiskyToggles =
        { "ssh.inEnabled", "ssh.outEnabled", "curl.useProxy", "curl.skipSsl", "ip.useProxy", "checkhost.useProxy", "cf.useProxy",
          "tg.useProxy", "monitor.tg.useProxy", "monitor.tg.enabled",
          // a backup's monitors must not start polling (at every launch / phone boot) before the user has looked at them
          "monitor.autoStart", "monitor.bootStart",
          // the Web Server hub without its PIN / over plain HTTP: "on" means less safe
          "webserver.noPin", "webserver.plainHttp" };

    // Switches whose ABSENCE means "on when an address is saved" (the Telegram tool, before its switch existed): a backup
    // that leaves the switch out but names a proxy gets the switch written as off.
    private static readonly (string Toggle, string Address)[] ImplicitToggles = { ("tg.useProxy", "tg.proxy") };

    // Routing with no switch at all (used whenever it is set): not taken over from a backup.
    // (the Web Server hub's PIN and certificate key too: a backup must not bring ones someone else knows; this install
    // makes new ones by itself)
    // (and its list of received files: a planted list could point Clean up at files that were never received)
    private static readonly string[] ClearedOnImport = { "socket.wsProxy", "webserver.pin", "webserver.cert", "webserver.received" };

    private static bool IsRiskyToggle(string key)
        => Array.IndexOf(RiskyToggles, key) >= 0
           || key.EndsWith(".useProxy", StringComparison.OrdinalIgnoreCase)
           || key.Contains("skipSsl", StringComparison.OrdinalIgnoreCase)
           || key.Contains("skipTls", StringComparison.OrdinalIgnoreCase);

    // The same for SSH settings held as JSON: a saved server's proxy / SOCKS tunnel come in switched off, and port
    // forwards (the current ones and each saved server's) don't come in at all — a planted -R forward would publish a
    // local service on the backup's server, a -L one could open a listener on the LAN, the moment the user connects.
    private static void DisarmSshImport(Dictionary<string, string> settings, List<string> disabled)
    {
        if (settings.TryGetValue("ssh.forwards", out var fwd) && fwd.Trim() is { Length: > 0 } f && f != "[]")
        {
            settings.Remove("ssh.forwards");
            disabled.Add("ssh.forwards");
        }
        if (!settings.TryGetValue("ssh.servers", out var list) || list.Length == 0) return;
        JsonArray? servers;
        try { servers = JsonNode.Parse(list) as JsonArray; }
        catch (System.Text.Json.JsonException) { servers = null; }
        if (servers is null)
        {
            settings.Remove("ssh.servers");   // unreadable: the SSH tool would ignore it anyway
            return;
        }
        foreach (var s in servers.OfType<JsonObject>())
        {
            foreach (var k in new[] { "proxy", "tunnel" })
                if (s[k] is JsonObject o && o["on"] is JsonValue v && v.TryGetValue(out bool on) && on)
                {
                    o["on"] = false;
                    if (!disabled.Contains("ssh.servers/" + k)) disabled.Add("ssh.servers/" + k);
                }
            if (s["fwd"] is JsonArray { Count: > 0 })
            {
                s["fwd"] = new JsonArray();
                if (!disabled.Contains("ssh.servers/forwards")) disabled.Add("ssh.servers/forwards");
            }
        }
        settings["ssh.servers"] = servers.ToJsonString();
    }

    // cURL's saved requests (one sealed JSON value) carry their own connection settings, applied when the user opens one:
    // a planted proxy, TLS skip or address override would send that request (with the user's own Authorization header)
    // through the backup author's machine. They come in without them.
    private static void DisarmCurlSavedImport(Dictionary<string, string> settings, List<string> disabled)
    {
        const string key = "curl.saved";
        if (!settings.TryGetValue(key, out var value) || value.Length == 0) return;
        bool carried = value.StartsWith(BackupPlainPrefix, StringComparison.Ordinal);
        string json;
        if (carried)
        {
            try { json = Encoding.UTF8.GetString(Convert.FromBase64String(value[BackupPlainPrefix.Length..])); }
            catch (FormatException) { return; }   // SealBackupValue drops a damaged value
        }
        else if (value.TrimStart().StartsWith('{')) json = value;
        else return;   // sealed with another install's key: it can't be opened here anyway

        JsonObject? root;
        try { root = JsonNode.Parse(json) as JsonObject; }
        catch (System.Text.Json.JsonException) { root = null; }
        if (root?["items"] is not JsonArray items)
        {
            settings.Remove(key);   // unreadable: the cURL tool would ignore it anyway
            return;
        }
        bool changed = false;
        foreach (var req in items.OfType<JsonObject>().Select(i => i["req"]).OfType<JsonObject>())
        {
            if (req["insecure"] is JsonValue v && v.TryGetValue(out bool insecure) && insecure)
            {
                req["insecure"] = false;
                changed = true;
            }
            foreach (var k in new[] { "proxy", "proxyUser", "proxyPass", "overrideIp" })
                changed |= req.Remove(k);
        }
        if (!changed) return;
        string rewritten = root.ToJsonString();
        settings[key] = carried ? BackupPlainPrefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(rewritten)) : rewritten;
        disabled.Add(key);
    }

    // A known-hosts key ("host:port", IPv6 hosts included) as SshHostKeyCheck.PinId spells it: host trimmed, without a
    // trailing dot, lower-case.
    private static string NormalizePinId(string key)
    {
        int colon = key.LastIndexOf(':');
        return colon <= 0
            ? key.Trim().ToLowerInvariant()
            : key[..colon].Trim().TrimEnd('.').ToLowerInvariant() + key[colon..].Trim();
    }

    /// <summary>What a backup import changed beyond a plain restore.</summary>
    public sealed record ImportReport(IReadOnlyList<string> DisabledToggles, int PinsKept);

    // ---------- Backup export ----------
    // Values sealed with SecretProtector use this install's own key file, which a backup doesn't carry: restored as-is
    // they'd decrypt to "" (saved proxy passwords lost — even on the same machine after a reinstall). So a backup carries
    // them as plaintext under this marker — the backup file itself is password-encrypted — and the import seals them
    // again with the local key.
    private const string BackupPlainPrefix = "bak1:";

    /// <summary>The profile as JSON for a backup bundle, built from the in-memory state (so pending writes are
    /// included); sealed settings are carried as <see cref="BackupPlainPrefix"/> values.</summary>
    public string ExportForBackup()
    {
        List<(string Key, List<string> Values)> history;
        Dictionary<string, string> settings, hosts;
        lock (_gate)
        {
            history = _history.Select(kv => (kv.Key, kv.Value.ToList())).ToList();
            settings = new Dictionary<string, string>(_settings);
            hosts = new Dictionary<string, string>(_knownHosts);
        }
        foreach (var key in settings.Keys.ToList())
        {
            if (!SecretProtector.IsProtected(settings[key])) continue;
            string plain = SecretProtector.Unprotect(settings[key]);
            // A value this install can't open stays sealed (it would restore as empty either way).
            if (plain.Length > 0) settings[key] = BackupPlainPrefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));
        }
        return Encoding.UTF8.GetString(Serialize(history.Select(h => (h.Key, (IEnumerable<string>)h.Values)), settings, hosts));
    }

    private static string SealBackupValue(string carried)
    {
        try { return SecretProtector.Protect(Encoding.UTF8.GetString(Convert.FromBase64String(carried[BackupPlainPrefix.Length..]))); }
        catch (FormatException) { return string.Empty; }   // damaged / hand-edited value: drop it rather than store it raw
    }

    /// <summary>
    /// Backup import: replace the profile with <paramref name="json"/>, persist it and refresh the in-memory stores, all
    /// under the gates — a concurrent background write can neither race the file nor serialize pre-import state back
    /// over the restore. Not taken over blindly: every existing SSH host pin stays (the backup only adds hosts that
    /// aren't pinned yet, under any spelling of the host), every proxy / TLS-skip toggle and the monitor's Telegram alerts
    /// come in switched off, and a proxy without a switch (WebSocket) isn't taken over (all reported, so the user can
    /// re-enable what they meant). History collections are refilled in place so live UI bindings stay attached — call on the UI
    /// thread. Throws on invalid JSON or a failed write; the in-memory state is then unchanged.
    /// </summary>
    public ImportReport ImportBackup(string json)
    {
        var root = ParseProfile(json);
        var settings = ReadMap(root["settings"]);
        var importedHosts = ReadMap(root["knownHosts"]);
        var history = ReadHistory(root["history"], out _);

        var disabled = new List<string>();
        DisarmCurlSavedImport(settings, disabled);   // before the sealing below: it reads the carried plain JSON

        // Secrets the backup carries in the clear (see ExportForBackup) are sealed again with this install's key.
        foreach (var key in settings.Keys.ToList())
            if (settings[key].StartsWith(BackupPlainPrefix, StringComparison.Ordinal))
                settings[key] = SealBackupValue(settings[key]);

        foreach (var (toggle, address) in ImplicitToggles)
            if (!settings.ContainsKey(toggle) && settings.TryGetValue(address, out var addr) && addr.Trim().Length > 0)
            {
                settings[toggle] = "false";
                disabled.Add(toggle);
            }
        foreach (var key in settings.Keys.ToList())
            if (IsRiskyToggle(key) && !string.Equals(settings[key], "false", StringComparison.OrdinalIgnoreCase))
            {
                if (bool.TryParse(settings[key], out bool on) && on) disabled.Add(key);
                settings[key] = "false";
            }
        foreach (var key in ClearedOnImport)
            if (settings.Remove(key, out var v) && v.Trim().Length > 0) disabled.Add(key);
        DisarmSshImport(settings, disabled);

        lock (_writeGate)
        lock (_gate)
        {
            var hosts = new Dictionary<string, string>(_knownHosts);
            // This device's pins by the SSH tool's normalized id: one an earlier build stored under the spelling as typed
            // ("MyHost:22") is still read as the fallback, and a backup pin under the normalized id ("myhost:22") — read
            // FIRST — must not shadow it.
            var pinned = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var kv in hosts) pinned.TryAdd(NormalizePinId(kv.Key), kv.Value);
            int kept = 0;
            foreach (var kv in importedHosts)
            {
                if (!pinned.TryGetValue(NormalizePinId(kv.Key), out var pin))
                {
                    hosts[kv.Key] = kv.Value;
                    pinned[NormalizePinId(kv.Key)] = kv.Value;
                }
                else if (!string.Equals(pin, kv.Value, StringComparison.OrdinalIgnoreCase)) kept++;
            }

            // Persist FIRST: if the write fails, nothing in memory has changed. (A profile that failed to load is kept
            // as .corrupt.bak if possible; the restore replaces it either way — that's what the user asked for.)
            if (_unreadable) SetAsideUnreadable();
            AppStorage.WriteAllBytesAtomic(_path, Serialize(history.Select(kv => (kv.Key, (IEnumerable<string>)kv.Value)), settings, hosts));
            _unreadable = false;

            _settings.Clear();
            foreach (var kv in settings) _settings[kv.Key] = kv.Value;
            _knownHosts.Clear();
            foreach (var kv in hosts) _knownHosts[kv.Key] = kv.Value;
            ReplaceHistoryLocked(history);
            _savedVersion = ++_version;   // the file now matches memory
            _restorePending = true;       // and stays as restored until the restart (see Save)
            return new ImportReport(disabled, kept);
        }
    }

    /// <summary>Throws unless <paramref name="json"/> is a profile document (a JSON object). Lets a backup
    /// restore reject a bad profile BEFORE it writes anything.</summary>
    public static void ValidateJson(string json) => ParseProfile(json);

    private static JsonObject ParseProfile(string json)
        => JsonNode.Parse(json) as JsonObject ?? throw new InvalidOperationException("Invalid profile JSON.");

    // Tolerant string read: a non-string value (hand-edited / foreign file) becomes "" instead of throwing
    // half-way through a load or a restore.
    private static string Str(JsonNode? n) => n is JsonValue v && v.TryGetValue(out string? s) ? s : string.Empty;

    private static Dictionary<string, string> ReadMap(JsonNode? node)
    {
        var map = new Dictionary<string, string>();
        if (node is JsonObject o)
            foreach (var kv in o) map[kv.Key] = Str(kv.Value);
        return map;
    }

    // History lists from the file (the profile, or a backup being imported), held to what AddHistory itself keeps: no
    // empty or oversized entries, at most MaxPerKey per list (the newest — index 0 — first), and no credentials (entries
    // an earlier build stored with a user:password@ in them; one that becomes a duplicate is folded). changed = the file
    // held anything that was dropped or cleaned, so it is worth re-writing.
    private static Dictionary<string, List<string>> ReadHistory(JsonNode? node, out bool changed)
    {
        changed = false;
        var map = new Dictionary<string, List<string>>();
        if (node is not JsonObject h) return map;
        foreach (var kv in h)
        {
            if (kv.Value is not JsonArray arr) continue;
            var list = new List<string>(Math.Min(arr.Count, MaxPerKey));
            foreach (var n in arr)
            {
                string s = Str(n);
                if (s.Length == 0) continue;
                if (s.Length > MaxEntryChars || list.Count >= MaxPerKey) { changed = true; continue; }
                string clean = Sanitize(s);
                if (!string.Equals(clean, s, StringComparison.Ordinal)) changed = true;
                if (clean.Length == 0 || list.Contains(clean)) { changed = true; continue; }
                list.Add(clean);
            }
            map[kv.Key] = list;
        }
        return map;
    }

    // Refill the live history collections IN PLACE (cleared + repopulated, not replaced) so bound UI stays attached.
    private void ReplaceHistoryLocked(Dictionary<string, List<string>> fresh)
    {
        foreach (var key in _history.Keys)
            if (!fresh.ContainsKey(key)) _history[key].Clear();     // gone in the restore
        foreach (var kv in fresh)
        {
            var list = GetHistoryLocked(kv.Key);
            list.Clear();
            foreach (var v in kv.Value) list.Add(v);
        }
        _historyVersion++;
    }

    // Re-read the profile file from disk and refresh the in-memory stores IN PLACE (pending changes are written first).
    public void Reload()
    {
        lock (_writeGate)
        {
            Flush();   // Monitor is re-entrant
            JsonObject? root;
            try { root = File.Exists(_path) ? JsonNode.Parse(File.ReadAllText(_path)) as JsonObject : null; }
            catch { return; }        // unreadable → keep current in-memory state
            if (root is null) return;
            lock (_gate)
            {
                var settings = ReadMap(root["settings"]);
                var hosts = ReadMap(root["knownHosts"]);
                _settings.Clear();
                foreach (var kv in settings) _settings[kv.Key] = kv.Value;
                _knownHosts.Clear();
                foreach (var kv in hosts) _knownHosts[kv.Key] = kv.Value;
                ReplaceHistoryLocked(ReadHistory(root["history"], out _));
                _savedVersion = _version;   // memory == file
            }
        }
    }

    // ---------- Persistence ----------
    private void Load()
    {
        try
        {
            Parse(ReadProfileText());
            return;
        }
        catch (FileNotFoundException) { }   // first run
        catch (Exception ex)
        {
            // (A DirectoryNotFoundException lands here too: UserDir() has just made the folder, so a missing one means the
            // data folder wasn't reachable, e.g. a network home not mounted yet at sign-in. Not a first run.)
            // Corrupt or unreadable: start fresh so the app still runs, but nothing is written over the file until it has
            // been kept as .corrupt.bak (SetAsideUnreadable, before the first write). The copy that used to be made right
            // here needed the very read access that had just failed, so a profile that was merely unreadable (locked by
            // another process, an offline OneDrive placeholder, a dropped network share) was overwritten by the first save
            // with no copy left. Until then it stays in place: the next launch may well read it.
            CrashLog.Write("Profile.Load", ex);
            _unreadable = true;
        }
        MigrateLegacy();
    }

    // A sharing violation (an AV scan, a backup tool) is usually over a moment later.
    private string ReadProfileText()
    {
        for (int attempt = 0; ; attempt++)
        {
            try { return File.ReadAllText(_path); }
            catch (IOException ex) when (attempt < 2 && ex is not (FileNotFoundException or DirectoryNotFoundException))
            {
                Thread.Sleep(50);
            }
        }
    }

    // The profile that failed to load, before anything is written over it: looked at again first. Gone → nothing to keep;
    // still unreadable → wait (false); it reads now → it was only locked or offline at startup, and this session started
    // from defaults: it is left alone (_keepDiskProfile) and the next launch loads it; corrupt → MOVED aside under a name of
    // its own (a rename needs no read access, and an earlier .corrupt.bak stays). Caller holds _writeGate.
    private bool SetAsideUnreadable()
    {
        try
        {
            string text = File.ReadAllText(_path);
            bool valid;
            try { valid = JsonNode.Parse(text) is JsonObject; }
            catch { valid = false; }
            if (valid)
            {
                _keepDiskProfile = true;
                CrashLog.Write("Profile.Load", new IOException("The profile couldn't be read at startup but can now: it is kept as it is, and this session's changes aren't saved."));
                return false;
            }
        }
        catch (FileNotFoundException) { return true; }   // nothing there (any more) to keep
        catch (IOException) { return false; }             // still locked / unreachable (incl. a missing folder)
        catch (UnauthorizedAccessException) { }           // can't be read, but maybe renamed: set it aside below
        catch { return false; }
        try { File.Move(_path, string.Create(CultureInfo.InvariantCulture, $"{_path}.corrupt-{DateTime.UtcNow:yyyyMMdd-HHmmss}.bak"), overwrite: false); }
        catch (FileNotFoundException) { }   // nothing there (any more) to keep
        catch { return false; }
        return true;
    }

    // Set when the profile that couldn't be read at startup reads fine later: nothing is written over it this session.
    private volatile bool _keepDiskProfile;

    private void Parse(string text)
    {
        if (JsonNode.Parse(text) is not JsonObject root) return;

        var history = ReadHistory(root["history"], out bool changed);
        foreach (var kv in history)
            _history[kv.Key] = new ObservableCollection<string>(kv.Value);

        foreach (var kv in ReadMap(root["settings"])) _settings[kv.Key] = kv.Value;
        foreach (var kv in ReadMap(root["knownHosts"])) _knownHosts[kv.Key] = kv.Value;

        // Oversized / surplus entries or stored credentials from an earlier build were dropped: write the cleaned profile
        // (in the background).
        if (changed) lock (_gate) Save();
    }

    // Set by a backup import: the file on disk IS the restore from then on. Every live view-model (Monitor, cURL, Port
    // Scanner, SSH, String Lab …) still holds its pre-import values and would write them back on its next change or at the
    // exit flush, e.g. turning the backup's monitors back on at the next launch. Until the restart the import asks for,
    // changes stay in memory only.
    private volatile bool _restorePending;

    // Caller holds _gate: mark the profile dirty and schedule one coalesced background write.
    private void Save()
    {
        if (_restorePending) return;
        _version++;
        if (_writeScheduled) return;
        _writeScheduled = true;
        _ = Task.Delay(WriteDelayMs).ContinueWith(_ => Flush(), TaskScheduler.Default);
    }

    /// <summary>
    /// Write pending changes now, synchronously (atomic). Safe from any thread except while holding a ProfileService lock;
    /// never throws. Returns false if a write was needed and failed (the profile stays dirty and is retried later).
    /// </summary>
    public bool Flush()
    {
        lock (_writeGate)
        {
            byte[] data;
            long version;
            lock (_gate)
            {
                _writeScheduled = false;
                if (_savedVersion == _version || _restorePending || _keepDiskProfile) return true;
                data = Serialize(_history.Select(kv => (kv.Key, (IEnumerable<string>)kv.Value)), _settings, _knownHosts);
                version = _version;
            }
            try
            {
                // Outside _gate: UI-thread readers / mutators never wait for the disk, only for the serialization.
                if (_unreadable && !SetAsideUnreadable()) return false;   // stays dirty: retried by the next change / Flush
                AppStorage.WriteAllBytesAtomic(_path, data);
                _unreadable = false;   // the file is ours now
                _savedVersion = version;
                return true;
            }
            catch
            {
                return false;   // disk full / locked: stays dirty — the next change or Flush retries
            }
        }
    }

    private static byte[] Serialize(IEnumerable<(string Key, IEnumerable<string> Values)> history,
                                    IEnumerable<KeyValuePair<string, string>> settings,
                                    IEnumerable<KeyValuePair<string, string>> knownHosts)
    {
        var h = new JsonObject();
        foreach (var (key, values) in history)
        {
            var arr = new JsonArray();
            // Cast to JsonNode so the non-generic Add(JsonNode?) is chosen (AOT-safe;
            // the generic Add<T> is RequiresDynamicCode).
            foreach (var v in values) arr.Add((JsonNode?)v);
            h[key] = arr;
        }
        var s = new JsonObject();
        foreach (var kv in settings) s[kv.Key] = kv.Value;
        var k = new JsonObject();
        foreach (var kv in knownHosts) k[kv.Key] = kv.Value;

        var root = new JsonObject { ["history"] = h, ["settings"] = s, ["knownHosts"] = k };
        return Encoding.UTF8.GetBytes(root.ToJsonString());
    }

    private void BackgroundInit()
    {
        try
        {
            SecretProtector.WarmUp();
            MigrateLegacySecrets();
        }
        catch (Exception ex) { CrashLog.Write("Profile.BackgroundInit", ex); }
    }

    // Re-seal every "enc1:" setting (machine-name-derived key, see SecretProtector) under the per-install key, so it no
    // longer depends on a hostname that macOS changes with the network. A value that doesn't open here is left as it is
    // (the host name may come back); one changed meanwhile by its tool is never overwritten.
    private void MigrateLegacySecrets()
    {
        List<KeyValuePair<string, string>> legacy;
        lock (_gate) legacy = _settings.Where(kv => SecretProtector.IsLegacy(kv.Value)).ToList();
        if (legacy.Count == 0) return;

        var upgraded = new List<(string Key, string Old, string New)>();
        foreach (var (key, old) in legacy)
        {
            string plain = SecretProtector.Unprotect(old);
            if (plain.Length == 0) continue;
            string resealed = SecretProtector.Protect(plain);
            if (!SecretProtector.IsLegacy(resealed)) upgraded.Add((key, old, resealed));   // no key file → stays enc1
        }
        if (upgraded.Count == 0) return;

        lock (_gate)
        {
            bool any = false;
            foreach (var (key, old, resealed) in upgraded)
                if (_settings.TryGetValue(key, out var cur) && cur == old) { _settings[key] = resealed; any = true; }
            if (any) Save();
        }
    }

    // One-time import from the old per-feature files, then delete them (single-file profile).
    private void MigrateLegacy()
    {
        bool any = false;

        try
        {
            var hp = AppStorage.ResolvePath("history.dat");
            if (File.Exists(hp) && JsonNode.Parse(File.ReadAllText(hp)) is JsonObject node
                && node["Entries"] is JsonObject entries)
            {
                foreach (var kv in entries)
                    if (kv.Value is JsonArray arr)
                        _history[kv.Key] = new ObservableCollection<string>(
                            arr.Select(n => n?.GetValue<string>() ?? string.Empty)
                               .Where(s => s.Length > 0 && s.Length <= MaxEntryChars));
                any = true;
            }
        }
        catch { }

        try
        {
            var dp = AppStorage.ResolvePath("dns_settings.txt");
            if (File.Exists(dp)) { _settings["dns.servers"] = File.ReadAllText(dp); any = true; }
        }
        catch { }

        try
        {
            var cp = AppStorage.UserPath("cloudflare.dat");
            if (File.Exists(cp) && JsonNode.Parse(File.ReadAllText(cp)) is JsonObject n)
            {
                _settings["cf.useToken"] = (n["useToken"]?.GetValue<bool>() ?? true) ? "true" : "false";
                _settings["cf.token"] = n["token"]?.GetValue<string>() ?? string.Empty;
                _settings["cf.email"] = n["email"]?.GetValue<string>() ?? string.Empty;
                _settings["cf.key"] = n["key"]?.GetValue<string>() ?? string.Empty;
                _settings["cf.useProxy"] = (n["useProxy"]?.GetValue<bool>() ?? false) ? "true" : "false";
                _settings["cf.proxy"] = n["proxy"]?.GetValue<string>() ?? string.Empty;
                any = true;
            }
        }
        catch { }

        try
        {
            var kp = AppStorage.UserPath("known_hosts.txt");
            if (File.Exists(kp))
            {
                foreach (var line in File.ReadAllLines(kp))
                {
                    var parts = line.Split(' ', 2);
                    if (parts.Length == 2) _knownHosts[parts[0].Trim()] = parts[1].Trim();
                }
                any = true;
            }
        }
        catch { }

        if (!any) return;
        lock (_gate) Save();
        // The old files go only once the profile holding their data is on disk.
        if (!Flush()) return;
        TryDelete(AppStorage.ResolvePath("history.dat"));
        TryDelete(AppStorage.ResolvePath("dns_settings.txt"));
        TryDelete(AppStorage.UserPath("cloudflare.dat"));
        TryDelete(AppStorage.UserPath("known_hosts.txt"));
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
