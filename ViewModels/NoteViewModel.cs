using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public class NoteItem : ObservableObject
{
    private string _title = string.Empty;
    public string Title { get => _title; set => SetProperty(ref _title, value); }

    private string _content = string.Empty;
    public string Content { get => _content; set => SetProperty(ref _content, value); }

    // UI-only: when true, the card shows the "Delete? ✓ ✗" confirmation overlay. Not persisted.
    private bool _pendingDelete;
    [JsonIgnore]
    public bool PendingDelete { get => _pendingDelete; set => SetProperty(ref _pendingDelete, value); }
}

public class NotePackage
{
    public string AuthTag { get; set; } = "ECHOES_VERIFIED_V1";
    public List<NoteItem> Notes { get; set; } = new();
}

[JsonSerializable(typeof(NotePackage))]
[JsonSerializable(typeof(List<NoteItem>))]
[JsonSerializable(typeof(NoteItem))]
internal partial class NotePackageContext : JsonSerializerContext
{
}

public partial class NoteViewModel : ObservableObject
{
    private readonly string _filePath = AppStorage.UserPath("notes.dat");

    // Current format: [magic(4)][version(1)][salt(16)][nonce(12)][tag(16)][ciphertext]
    private static readonly byte[] Magic = { 0x45, 0x43, 0x48, 0x76 }; // "ECHv"
    private const byte FormatVersion = 2;
    private const int Pbkdf2Iterations = 600_000;
    // Legacy v1 parameters (AES-CBC, fixed salt, 5000 iters) — kept only to migrate old files.
    private readonly byte[] _legacySalt = Encoding.UTF8.GetBytes("Echoes_Fixed_Salt_Unique_2026");

    [ObservableProperty] private ObservableCollection<NoteItem> _notes = new();
    [ObservableProperty] private ObservableCollection<NoteItem> _filteredNotes = new();
    [ObservableProperty] private string _searchQuery = string.Empty;
    [ObservableProperty] private NoteItem? _selectedNote;
    [ObservableProperty] private bool _isEditing;
    [ObservableProperty] private bool _isLocked = true;
    [ObservableProperty] private string _masterKey = string.Empty;
    [ObservableProperty] private string _errorMessage = string.Empty;

    private bool _isAuthenticated = false;

    public NoteViewModel()
    {
        // Share one master password with Cloudflare + Sync: if the app is already unlocked
        // elsewhere, open silently with the same credential.
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

    partial void OnNotesChanged(ObservableCollection<NoteItem> value) => ApplyFilter();
    partial void OnSearchQueryChanged(string value) => ApplyFilter();

    private void ApplyFilter()
    {
        string q = SearchQuery?.Trim() ?? string.Empty;
        FilteredNotes = q.Length == 0
            ? new ObservableCollection<NoteItem>(Notes)
            : new ObservableCollection<NoteItem>(Notes.Where(n =>
                n.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                n.Content.Contains(q, StringComparison.OrdinalIgnoreCase)));
    }

    [RelayCommand]
    private void Unlock() => TryUnlock(MasterKey, silent: false);

    // Attempt to unlock with the given password. silent=true suppresses error text (used for the
    // shared-session auto-unlock, where a mismatch just leaves the manual prompt showing).
    private bool TryUnlock(string password, bool silent)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            if (!silent) ErrorMessage = "Enter a Master Key.";
            return false;
        }

        if (!File.Exists(_filePath))
        {
            // First run: this password becomes the master.
            MasterKey = password;
            _isAuthenticated = true;
            IsLocked = false;
            Notes = new ObservableCollection<NoteItem>();
            ErrorMessage = string.Empty;
            SaveNotes();
            MasterSession.Set(password);
            return true;
        }

        try
        {
            byte[] data = File.ReadAllBytes(_filePath);
            string decrypted = Decrypt(data, password, out bool legacy);
            var package = JsonSerializer.Deserialize(decrypted, NotePackageContext.Default.NotePackage);

            if (package != null && package.AuthTag == "ECHOES_VERIFIED_V1")
            {
                MasterKey = password;
                Notes = new ObservableCollection<NoteItem>(package.Notes);
                _isAuthenticated = true;
                IsLocked = false;
                ErrorMessage = string.Empty;

                // Migrate an old AES-CBC file to the authenticated AES-GCM format.
                if (legacy) SaveNotes();

                MasterSession.Set(password);   // let Cloudflare / Sync ride the same credential
                return true;
            }

            if (!silent) ErrorMessage = "Decryption failed. Wrong key?";
            return false;
        }
        catch (Exception ex)
        {
            _isAuthenticated = false;
            if (!silent) ErrorMessage = "Error: " + ex.Message;
            return false;
        }
    }

    private void SaveNotes()
    {
        if (IsLocked || !_isAuthenticated || string.IsNullOrWhiteSpace(MasterKey)) return;

        try
        {
            var package = new NotePackage { Notes = Notes.ToList() };
            string json = JsonSerializer.Serialize(package, NotePackageContext.Default.NotePackage);
            byte[] encrypted = Encrypt(json, MasterKey);
            File.WriteAllBytes(_filePath, encrypted);
        }
        catch (Exception ex)
        {
            ErrorMessage = "Save Failed: " + ex.Message;
        }
    }

    private byte[] Encrypt(string plainText, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);

        byte[] plain = Encoding.UTF8.GetBytes(plainText);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[16];

        try
        {
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(nonce, plain, cipher, tag);
        }
        finally { Array.Clear(key); }

        using var ms = new MemoryStream();
        ms.Write(Magic);
        ms.WriteByte(FormatVersion);
        ms.Write(salt);
        ms.Write(nonce);
        ms.Write(tag);
        ms.Write(cipher);
        return ms.ToArray();
    }

    private string Decrypt(byte[] data, string password, out bool legacy)
    {
        if (IsCurrentFormat(data))
        {
            legacy = false;
            int o = Magic.Length + 1;
            byte[] salt = data.AsSpan(o, 16).ToArray(); o += 16;
            byte[] nonce = data.AsSpan(o, 12).ToArray(); o += 12;
            byte[] tag = data.AsSpan(o, 16).ToArray(); o += 16;
            byte[] cipher = data.AsSpan(o).ToArray();

            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
            byte[] plain = new byte[cipher.Length];
            try
            {
                using var gcm = new AesGcm(key, 16);
                gcm.Decrypt(nonce, cipher, tag, plain); // throws on wrong key / tampering
            }
            finally { Array.Clear(key); }

            return Encoding.UTF8.GetString(plain);
        }

        legacy = true;
        return DecryptLegacy(data, password);
    }

    private bool IsCurrentFormat(byte[] data)
    {
        if (data.Length < Magic.Length + 1 + 16 + 12 + 16) return false;
        for (int i = 0; i < Magic.Length; i++)
            if (data[i] != Magic[i]) return false;
        return data[Magic.Length] == FormatVersion;
    }

    private string DecryptLegacy(byte[] cipherData, string password)
    {
        using Aes aes = Aes.Create();
        using var pbkdf2 = new Rfc2898DeriveBytes(password, _legacySalt, 5000, HashAlgorithmName.SHA256);
        aes.Key = pbkdf2.GetBytes(32);
        aes.IV = pbkdf2.GetBytes(16);

        using var ms = new MemoryStream(cipherData);
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new StreamReader(cs);
        return reader.ReadToEnd();
    }

    [RelayCommand]
    private void AddNote()
    {
        if (IsLocked) return;
        Notes.Add(new NoteItem { Title = "New Note " + (Notes.Count + 1) });
        SaveNotes();
        ApplyFilter();
        OpenNote(Notes.Last());
    }

    [RelayCommand]
    private void OpenNote(NoteItem note)
    {
        if (IsLocked) return;
        SelectedNote = note;
        IsEditing = true;
    }

    [RelayCommand]
    private void BackToList()
    {
        SaveNotes();
        IsEditing = false;
        SelectedNote = null;
        ApplyFilter();   // reflect any title/content edits in the (possibly filtered) list
    }

    // First click: arm the inline confirmation on this card (and disarm any other).
    [RelayCommand]
    private void RequestDeleteNote(NoteItem note)
    {
        if (IsLocked) return;
        foreach (var n in Notes) n.PendingDelete = false;
        note.PendingDelete = true;
    }

    [RelayCommand]
    private void CancelDeleteNote(NoteItem note) => note.PendingDelete = false;

    // Second click (the ✓): actually remove the note.
    [RelayCommand]
    private void DeleteNote(NoteItem note)
    {
        if (IsLocked) return;
        Notes.Remove(note);
        SaveNotes();
        ApplyFilter();
        if (SelectedNote == note) BackToList();
    }

    // User pressed LOCK: lock this tab AND drop the shared session so Cloudflare/Sync re-lock too.
    [RelayCommand]
    private void LockApp()
    {
        LockInternal();
        MasterSession.Clear();
    }

    private void LockInternal()
    {
        if (!IsLocked && _isAuthenticated) SaveNotes();
        Notes.Clear();
        FilteredNotes.Clear();
        SearchQuery = string.Empty;
        MasterKey = string.Empty;
        _isAuthenticated = false;
        IsLocked = true;
        IsEditing = false;
    }
}