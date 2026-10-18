using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// Local, offline backup: bundle the app's data into a single password-encrypted file the user
/// exports and imports by hand — no server, no account. (Replaces the old cloud sync.)
///
/// <para>The crypto/bundle lives here; the actual file picking + read/write is done in the view's
/// code-behind, which needs the window's <c>StorageProvider</c>.</para>
/// </summary>
public partial class BackupViewModel : ObservableObject
{
    [ObservableProperty] private string _password = string.Empty;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _status = "Export to one encrypted file, or restore one.";

    // Build the encrypted backup bytes. Throws on bad input; the caller writes them to the chosen file.
    // Call on the UI thread: the data files are read here (alongside every other writer of them); only the
    // 600k-iteration PBKDF2 + AES runs on the thread pool, so the busy state can render meanwhile.
    public async Task<byte[]> BuildExportAsync()
    {
        if (string.IsNullOrEmpty(Password)) throw new InvalidOperationException("Enter a password to protect the backup.");
        if (Password.Length < 6) throw new InvalidOperationException("Use a password of at least 6 characters.");
        string bundle = BuildLocalBundle();
        char[] pw = SecureMemory.CopyChars(Password);   // pinned copy for the worker; zeroed below
        try { return await Task.Run(() => BackupVault.Encrypt(bundle, pw)); }
        finally { SecureMemory.Zero(pw); }
    }

    // Decrypt + restore a backup's bytes into the app's data files. Throws on wrong password / bad file.
    // Call on the UI thread: only the decrypt (PBKDF2) is moved off it. ApplyBundle must run back on the UI
    // thread — ProfileService repopulates history collections that live AutoCompleteBoxes are bound to.
    // Returns a note for the status line about what the import deliberately did NOT take over (empty if nothing).
    public async Task<string> ApplyImportAsync(byte[] data)
    {
        if (string.IsNullOrEmpty(Password)) throw new InvalidOperationException("Enter the backup's password.");
        char[] pw = SecureMemory.CopyChars(Password);
        byte[] inner;
        try { inner = await Task.Run(() => BackupVault.Decrypt(data, pw)); }
        finally { SecureMemory.Zero(pw); }
        try { return Describe(ApplyBundle(inner)); }
        finally { SecureMemory.Zero(inner); }   // the decrypted bundle (profile + notes) is parsed from these bytes only
    }

    /// <summary>Forget the typed password once it has done its job (export written / import applied).</summary>
    public void ClearPassword() => Password = string.Empty;

    // Everything the app persists, packed into one JSON document.
    private static string BuildLocalBundle()
    {
        string notesPath = AppStorage.UserPath("notes.dat");
        // Both files are written behind (background writers): put what's pending on disk before reading them.
        ProfileService.Instance.Flush();
        AppStorage.WriterFor(notesPath).Flush();
        // Not the raw file: saved proxy passwords are sealed with this install's own key, which the backup doesn't
        // carry — the export travels them inside the (password-encrypted) backup and the import re-seals them.
        string profile = ProfileService.Instance.ExportForBackup();
        string notes = File.Exists(notesPath) ? Convert.ToBase64String(File.ReadAllBytes(notesPath)) : string.Empty;
        return new JsonObject
        {
            ["app"] = "echoes",
            ["v"] = 1,
            ["profile"] = profile,   // settings, input history, known-hosts, encrypted cf.vault
            ["notes"] = notes        // notes.dat (stays encrypted with its own master key)
        }.ToJsonString();
    }

    private static ProfileService.ImportReport? ApplyBundle(byte[] innerUtf8)
    {
        // Decode + validate EVERYTHING before touching disk, so a malformed bundle changes nothing.
        if (JsonNode.Parse(innerUtf8.AsSpan()) is not JsonObject o) throw new InvalidOperationException("Corrupt backup contents.");
        string profile = (string?)o["profile"] ?? string.Empty;   // throws on a non-string → "Import failed"
        string notes = (string?)o["notes"] ?? string.Empty;
        byte[]? notesBytes = notes.Length > 0 ? Convert.FromBase64String(notes) : null;
        if (profile.Length > 0) ProfileService.ValidateJson(profile);

        bool touched = false;
        ProfileService.ImportReport? report = null;
        try
        {
            // Both writes are crash-safe (temp file + rename): a failure (e.g. disk full) leaves that file as it was.
            if (notesBytes is not null)
            {
                // Through notes.dat's shared writer: drops a not-yet-written autosave of the pre-restore notes and
                // waits for one in flight, so neither can land over the restored file afterwards.
                AppStorage.WriterFor(AppStorage.UserPath("notes.dat")).WriteNow(notesBytes);
                touched = true;
            }
            // Gated write + in-memory refresh so a concurrent background write can't race it or serialize stale
            // pre-import state back over the restore. Keeps existing SSH pins; turns proxy / TLS-skip toggles
            // and the monitor's Telegram alerts off.
            if (profile.Length > 0)
            {
                report = ProfileService.Instance.ImportBackup(profile);
                touched = true;
            }
        }
        finally
        {
            // Once ANY file was replaced (even if a later step failed), the live vault VMs (Notes, Cloudflare)
            // must drop their stale in-memory decrypted state WITHOUT saving — otherwise their next save
            // (or the exit flush) would overwrite the just-restored files.
            if (touched) MasterSession.NotifyRestoreApplied();
        }
        return report;
    }

    // Friendly names for the routing / TLS toggles an import switches off (ProfileService.ImportBackup).
    private static readonly Dictionary<string, string> ToggleLabels = new()
    {
        ["ssh.inEnabled"] = "SSH via SOCKS proxy",
        ["ssh.outEnabled"] = "SSH SOCKS tunnel",
        ["curl.useProxy"] = "cURL proxy",
        ["curl.skipSsl"] = "cURL skip TLS verify",
        ["ip.useProxy"] = "IP Info proxy",
        ["doctor.useProxy"] = "Doctor proxy",
        ["checkhost.useProxy"] = "Check-Host proxy",
        ["cf.useProxy"] = "Cloudflare proxy",
        ["tg.useProxy"] = "Telegram proxy",
        ["monitor.tg.useProxy"] = "Monitor's Telegram proxy",
        ["monitor.tg.enabled"] = "Monitor's Telegram alerts",
        ["monitor.autoStart"] = "Monitor's start with Echoes",
        ["monitor.bootStart"] = "Monitor's start at boot",
        ["curl.saved"] = "saved cURL requests' proxy, TLS skip and IP override",
        ["webserver.noPin"] = "Web Server without PIN",
        ["webserver.plainHttp"] = "Web Server plain HTTP",
        ["webserver.pin"] = "Web Server PIN (a new one is made)",
        ["webserver.cert"] = "Web Server certificate (a new one is made)",
        ["socket.wsProxy"] = "WebSocket proxy (not imported)",
        ["ssh.forwards"] = "SSH port forwards (not imported)",
        ["ssh.servers/proxy"] = "saved SSH servers' proxy",
        ["ssh.servers/tunnel"] = "saved SSH servers' SOCKS tunnel",
        ["ssh.servers/forwards"] = "saved SSH servers' port forwards (not imported)",
    };

    private static string Describe(ProfileService.ImportReport? report)
    {
        if (report is null) return string.Empty;
        var notes = new List<string>();
        if (report.DisabledToggles.Count > 0)
            notes.Add("Turned off for safety: "
                      + string.Join(", ", report.DisabledToggles.Select(k => ToggleLabels.TryGetValue(k, out var l) ? l : k))
                      + " — re-enable if intended.");
        if (report.PinsKept > 0)
            notes.Add($"Kept this device's SSH host key pin for {report.PinsKept} host(s); the backup's differed.");
        return string.Join("\n", notes);
    }
}
