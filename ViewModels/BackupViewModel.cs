using System;
using System.IO;
using System.Text.Json.Nodes;
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
    [ObservableProperty] private string _status = "Export everything to one encrypted file — or import it back.";

    // Build the encrypted backup bytes. Throws on bad input; the caller writes them to the chosen file.
    public byte[] BuildExport()
    {
        if (string.IsNullOrEmpty(Password)) throw new InvalidOperationException("Enter a password to protect the backup.");
        if (Password.Length < 6) throw new InvalidOperationException("Use a password of at least 6 characters.");
        return BackupVault.Encrypt(BuildLocalBundle(), Password);
    }

    // Decrypt + restore a backup's bytes into the app's data files. Throws on wrong password / bad file.
    public void ApplyImport(byte[] data)
    {
        if (string.IsNullOrEmpty(Password)) throw new InvalidOperationException("Enter the backup's password.");
        ApplyBundle(BackupVault.Decrypt(data, Password));
    }

    // Everything the app persists, packed into one JSON document.
    private static string BuildLocalBundle()
    {
        string profilePath = AppStorage.UserPath("echoes.profile.json");
        string notesPath = AppStorage.UserPath("notes.dat");
        string profile = File.Exists(profilePath) ? File.ReadAllText(profilePath) : "{}";
        string notes = File.Exists(notesPath) ? Convert.ToBase64String(File.ReadAllBytes(notesPath)) : string.Empty;
        return new JsonObject
        {
            ["app"] = "echoes",
            ["v"] = 1,
            ["profile"] = profile,   // settings, input history, known-hosts, encrypted cf.vault
            ["notes"] = notes        // notes.dat (stays encrypted with its own master key)
        }.ToJsonString();
    }

    private static void ApplyBundle(string inner)
    {
        if (JsonNode.Parse(inner) is not JsonObject o) throw new InvalidOperationException("Corrupt backup contents.");
        string profile = (string?)o["profile"] ?? string.Empty;
        string notes = (string?)o["notes"] ?? string.Empty;
        if (profile.Length > 0)
        {
            File.WriteAllText(AppStorage.UserPath("echoes.profile.json"), profile);
            // Refresh the running singleton from the restored file so a later Save() can't clobber it.
            // (Per-tool VM fields still need a restart to re-read, which the UI message says.)
            ProfileService.Instance.Reload();
        }
        if (notes.Length > 0) File.WriteAllBytes(AppStorage.UserPath("notes.dat"), Convert.FromBase64String(notes));
    }
}
