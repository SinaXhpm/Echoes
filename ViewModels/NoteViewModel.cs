using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

public class NoteItem : ObservableObject
{
    private string _title = string.Empty;
    public string Title { get => _title; set => SetProperty(ref _title, value); }

    private string _content = string.Empty;
    public string Content
    {
        get => _content;
        set { if (SetProperty(ref _content, value)) OnPropertyChanged(nameof(Preview)); }
    }

    // What the list card shows (two lines, ellipsis). Bound to the whole Content, the card's TextBlock wrapped ALL of it
    // to find those two lines — on every keystroke while the list sits beside the editor, and for every card shown:
    // ~0.4 s per keystroke for a 200 KB single-paragraph note (a pasted key / base64 blob). The first PreviewChars
    // characters overfill two lines at any card width, so the card looks the same. UI-only: never serialized.
    private const int PreviewChars = 512;
    [JsonIgnore]
    public string Preview
    {
        get
        {
            string c = _content;
            if (c.Length <= PreviewChars) return c;
            return c[..(char.IsHighSurrogate(c[PreviewChars - 1]) ? PreviewChars - 1 : PreviewChars)];
        }
    }

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
    // notes.dat is written on the thread pool (temp file + fsync + rename) so an autosave never stalls typing. Shared
    // with a backup restore; FlushPendingSave waits for it on exit and when the app is backgrounded.
    private readonly AtomicFileWriter _writer;

    // Current format: [magic(4)][version(1)][salt(16)][nonce(12)][tag(16)][ciphertext]
    private static readonly byte[] Magic = { 0x45, 0x43, 0x48, 0x76 }; // "ECHv"
    private const byte FormatVersion = 2;
    private const int Pbkdf2Iterations = 600_000;
    // Legacy v1 parameters (AES-CBC, fixed salt, 5000 iters) — kept only to migrate old files.
    private static readonly byte[] LegacySalt = Encoding.UTF8.GetBytes("Echoes_Fixed_Salt_Unique_2026");
    private const string WrongKey = "Decryption failed. Wrong key?";

    [ObservableProperty] private ObservableCollection<NoteItem> _notes = new();
    // Never replaced: filtering edits it in place, so the cards that stay visible aren't rebuilt on every keystroke.
    public ObservableCollection<NoteItem> FilteredNotes { get; } = new();
    [ObservableProperty] private string _searchQuery = string.Empty;
    [ObservableProperty] private NoteItem? _selectedNote;
    [ObservableProperty] private bool _isEditing;
    [ObservableProperty] private bool _isLocked = true;
    [ObservableProperty] private string _masterKey = string.Empty;
    [ObservableProperty] private string _errorMessage = string.Empty;

    // An unlock's 600k-iteration PBKDF2 runs on the thread pool (seconds on a phone — on the UI thread that froze the
    // window, ANR territory). Meanwhile the button reads "Unlocking…" and is disabled: one attempt at a time.
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UnlockLabel))]
    [NotifyCanExecuteChangedFor(nameof(UnlockCommand))]
    private bool _isUnlocking;
    public string UnlockLabel => IsUnlocking ? "Unlocking…" : "Unlock";

    // Bumped by lock / restore / a cleared session: an unlock still deriving at that moment is discarded when it lands.
    private int _unlockGen;

    private bool _isAuthenticated = false;

    // 32-byte key derived from the master password, cached for the unlocked SESSION so we don't re-run
    // 600k-iteration PBKDF2 on every save (which froze the UI ~0.5-1s per note action, esp. on Android).
    // A fresh random nonce per save keeps AES-GCM secure while the key + salt stay fixed for the session.
    private byte[]? _sessionKey;
    private byte[] _sessionSalt = Array.Empty<byte>();

    public NoteViewModel()
    {
        _writer = AppStorage.WriterFor(_filePath);
        _writer.WriteFailed += ex => Avalonia.Threading.Dispatcher.UIThread.Post(() => ErrorMessage = "Save Failed: " + ex.Message);

        // Share one master password with Cloudflare + Sync: if the app is already unlocked
        // elsewhere, open silently with the same credential.
        MasterSession.Changed += OnMasterSessionChanged;
        MasterSession.RestoreApplied += OnRestoreApplied;
        if (MasterSession.IsSet) _ = UnlockAsync(MasterSession.CopyPassword(), silent: true);
    }

    // A backup restore overwrote notes.dat on disk. Drop our stale in-memory notes + session key WITHOUT
    // saving (a save would clobber the restore) and lock — the user re-unlocks to read the restored notes.
    // Runs inline when already on the UI thread (the restore does), so a debounced autosave already queued
    // on the dispatcher finds us locked instead of writing the stale notes over the restored file.
    private void OnRestoreApplied()
    {
        if (Avalonia.Threading.Dispatcher.UIThread.CheckAccess()) DropForRestore();
        else Avalonia.Threading.Dispatcher.UIThread.Post(DropForRestore);
    }

    private void DropForRestore()
    {
        IsLocked = true;              // FIRST, so nothing below (or a queued autosave) can save
        _isAuthenticated = false;
        CancelUnlock();               // an unlock still deriving would reopen the pre-restore file's result
        CancelPendingSave();
        foreach (var n in Notes) n.PropertyChanged -= OnNoteEdited;
        Notes.Clear();
        FilteredNotes.Clear();
        SearchQuery = string.Empty;
        MasterKey = string.Empty;
        ClearSessionKey();
        IsEditing = false;
        ErrorMessage = string.Empty;
    }

    private void ClearSessionKey()
    {
        SecureMemory.Release(_sessionKey);   // zeroed in place (pinned, so no stale copies elsewhere)
        _sessionKey = null;
        _sessionSalt = Array.Empty<byte>();
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

    partial void OnNotesChanged(ObservableCollection<NoteItem> value) => ApplyFilter();

    // Debounced: each keystroke used to build a new collection and rebuild every card.
    private CancellationTokenSource? _filterCts;

    partial void OnSearchQueryChanged(string value)
    {
        _filterCts?.Cancel();
        _filterCts?.Dispose();
        var cts = _filterCts = new CancellationTokenSource();
        _ = Task.Delay(150, cts.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(ApplyFilter);
        }, TaskScheduler.Default);
    }

    private void ApplyFilter()
    {
        string q = SearchQuery?.Trim() ?? string.Empty;
        var target = q.Length == 0
            ? Notes.ToList()
            : Notes.Where(n => n.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                               n.Content.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();

        // Both lists follow Notes' order: drop the cards that no longer match, insert the missing ones in place.
        var keep = new HashSet<NoteItem>(target, ReferenceEqualityComparer.Instance);
        for (int i = FilteredNotes.Count - 1; i >= 0; i--)
            if (!keep.Contains(FilteredNotes[i])) FilteredNotes.RemoveAt(i);
        for (int i = 0; i < target.Count; i++)
            if (i >= FilteredNotes.Count || !ReferenceEquals(FilteredNotes[i], target[i])) FilteredNotes.Insert(i, target[i]);
        if (FilteredNotes.Count != target.Count)   // order drifted (nothing reorders notes) — never show a wrong list
        {
            FilteredNotes.Clear();
            foreach (var n in target) FilteredNotes.Add(n);
        }
    }

    [RelayCommand(CanExecute = nameof(CanUnlock))]
    private void Unlock() => _ = UnlockAsync(SecureMemory.CopyChars(MasterKey), silent: false);

    private bool CanUnlock() => !IsUnlocking;

    private void CancelUnlock()
    {
        _unlockGen++;
        IsUnlocking = false;
    }

    // Unlock with the given password: derive + decrypt on the thread pool, then apply on the UI thread. silent=true
    // suppresses error text (used for the shared-session auto-unlock, where a mismatch just leaves the manual prompt
    // showing). Takes ownership of the pinned password copy and zeroes it when the attempt is over.
    private async Task UnlockAsync(char[] password, bool silent)
    {
        try { await UnlockCoreAsync(password, silent); }
        finally { SecureMemory.Zero(password); }
    }

    private async Task UnlockCoreAsync(char[] password, bool silent)
    {
        if (IsUnlocking || !IsLocked) return;   // double click / Enter + click: the attempt in flight decides
        if (MemoryExtensions.IsWhiteSpace(password))
        {
            if (!silent) ErrorMessage = "Enter your master key.";
            return;
        }

        int gen = ++_unlockGen;
        int epoch = MasterSession.Epoch;
        IsUnlocking = true;
        if (!silent) ErrorMessage = string.Empty;

        VaultOpen result;
        try { result = await Task.Run(() => OpenVault(password)); }
        catch (Exception ex) { result = VaultOpen.Fail(ex is CryptographicException or JsonException ? WrongKey : "Error: " + ex.Message); }

        bool superseded = gen != _unlockGen;   // locked / restored here meanwhile (that already reset IsUnlocking)
        if (!superseded) IsUnlocking = false;
        if (superseded || epoch != MasterSession.Epoch)   // ... or LOCK / restore anywhere: never reopen what was just locked
        {
            result.Discard();
            return;
        }

        if (!result.Ok)
        {
            _isAuthenticated = false;
            if (!silent) ErrorMessage = result.Error;
            // The shared session may have moved on while this ran (another area unlocked with another password).
            if (MasterSession.IsSet && !MasterSession.Matches(password)) _ = UnlockAsync(MasterSession.CopyPassword(), silent: true);
            return;
        }

        ClearSessionKey();
        _sessionKey = result.Key;         // the session key: saves are AES-GCM + a file write, no PBKDF2
        SecureMemory.Track(_sessionKey);  // wiped at exit if still unlocked
        _sessionSalt = result.Salt;
        MasterKey = string.Empty;         // don't keep the typed key in the bound field: saves only need the session key
        foreach (var n in result.Notes) n.PropertyChanged += OnNoteEdited;
        Notes = new ObservableCollection<NoteItem>(result.Notes);
        _isAuthenticated = true;
        IsLocked = false;
        ErrorMessage = string.Empty;

        // First run creates the vault; an old AES-CBC file is migrated to the authenticated AES-GCM format.
        if (result.MustSave) SaveNotes();

        MasterSession.Set(password);   // let Cloudflare / Sync ride the same credential
    }

    // Result of an unlock attempt, built on the thread pool and applied on the UI thread.
    private sealed class VaultOpen
    {
        public bool Ok { get; init; }
        public string Error { get; init; } = string.Empty;
        public List<NoteItem> Notes { get; init; } = new();
        public byte[]? Key { get; init; }
        public byte[] Salt { get; init; } = Array.Empty<byte>();
        public bool MustSave { get; init; }   // first run, or a legacy file to re-encrypt

        public static VaultOpen Fail(string error) => new() { Error = error };
        public void Discard() => SecureMemory.Zero(Key);
    }

    // Thread pool. Touches only readonly fields; everything it learns goes back in the result.
    private VaultOpen OpenVault(char[] password)
    {
        _writer.Flush();   // an autosave still queued must be on disk before the file is read (or found missing)

        byte[] data;
        try { data = File.ReadAllBytes(_filePath); }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            // First run: this password becomes the master. Only when the vault is really missing: File.Exists also said
            // "no" when it merely couldn't be reached (a dropped network share), and the empty vault created then replaced
            // the real one once the writer's retry got through. "Folder not found" is that same case: the data folder is
            // created at startup, so its absence now means it can't be reached — unless it can be created again.
            if (ex is DirectoryNotFoundException)
            {
                try { Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!); }
                catch (Exception e) { throw new IOException("The notes folder can't be reached: " + e.Message, e); }
            }
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            return new VaultOpen { Ok = true, MustSave = true, Salt = salt, Key = DeriveKey(password, salt) };
        }
        byte[] decrypted = Decrypt(data, password, out bool legacy, out byte[]? key, out byte[]? fileSalt);
        NotePackage? package;
        // Parsed straight from the decrypted bytes (no string copy of every note), which are zeroed right after.
        try { package = JsonSerializer.Deserialize(decrypted, NotePackageContext.Default.NotePackage); }
        catch { SecureMemory.Zero(key); throw; }
        finally { SecureMemory.Zero(decrypted); }

        if (package is null || package.AuthTag != "ECHOES_VERIFIED_V1")
        {
            SecureMemory.Zero(key);
            return VaultOpen.Fail(WrongKey);
        }
        if (key is null || fileSalt is null)
        {
            // Legacy AES-CBC file: re-encrypted right after the unlock, under a fresh session key + salt.
            fileSalt = RandomNumberGenerator.GetBytes(16);
            key = DeriveKey(password, fileSalt);
        }
        return new VaultOpen { Ok = true, Notes = package.Notes, Key = key, Salt = fileSalt, MustSave = legacy };
    }

    private void SaveNotes()
    {
        if (IsLocked || !_isAuthenticated || _sessionKey is null) return;

        try
        {
            var package = new NotePackage { Notes = Notes.ToList() };
            // Serialized to UTF-8 bytes (not a string) so the plaintext buffer can be zeroed once it's encrypted.
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(package, NotePackageContext.Default.NotePackage);
            byte[] encrypted;
            try { encrypted = Encrypt(json); }
            finally { SecureMemory.Zero(json); }
            // Temp file + fsync + rename on the background writer: a full disk / kill mid-write must never truncate
            // the only copy of the vault, and the fsync no longer runs on the UI thread.
            _writer.Enqueue(encrypted);
            _savePending = false;
        }
        catch (Exception ex)
        {
            ErrorMessage = "Save Failed: " + ex.Message;
        }
    }

    // ---------- Autosave ----------
    // The editor TextBoxes write straight into SelectedNote.Title / .Content on every keystroke. Persist
    // those edits debounced, so closing the app (or Android killing it in the background) never loses
    // text typed since the last DONE. Cheap: the session key is cached, so a save is AES-GCM + a queued write.
    private CancellationTokenSource? _saveCts;
    private bool _savePending;   // an edit hasn't been written yet (UI thread only)

    private void OnNoteEdited(object? sender, PropertyChangedEventArgs e)
    {
        // PendingDelete is UI-only (not persisted) — only real content edits schedule a save.
        if (e.PropertyName is nameof(NoteItem.Title) or nameof(NoteItem.Content)) ScheduleSave();
    }

    private void ScheduleSave()
    {
        if (IsLocked || !_isAuthenticated) return;
        _savePending = true;
        _saveCts?.Cancel();
        _saveCts?.Dispose();
        var cts = _saveCts = new CancellationTokenSource();
        _ = Task.Delay(500, cts.Token).ContinueWith(t =>
        {
            if (!t.IsCanceled) Avalonia.Threading.Dispatcher.UIThread.Post(SavePendingEdit);
        }, TaskScheduler.Default);
    }

    private void CancelPendingSave()
    {
        _saveCts?.Cancel();
        _savePending = false;
    }

    private void SavePendingEdit()
    {
        if (_savePending && !IsLocked && _isAuthenticated) SaveNotes();
    }

    /// <summary>Write a pending (debounced) note edit and wait until notes.dat is on disk. Called on app shutdown and
    /// when the app is backgrounded. UI thread only.</summary>
    public void FlushPendingSave()
    {
        _saveCts?.Cancel();
        SavePendingEdit();
        _writer.Flush();
    }

    // Pinned key (SecureMemory): never moved by the GC, zeroed in place on lock / exit.
    private static byte[] DeriveKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt)
        => SecureMemory.Pbkdf2(password, salt, Pbkdf2Iterations, 32);

    // AES-GCM under the session key (derived ONCE per unlocked session, off the UI thread, at unlock) with a fresh nonce.
    // The ciphertext is written straight into the file image. Only called while unlocked (_sessionKey set).
    private byte[] Encrypt(byte[] plainUtf8)
    {
        byte[] key = _sessionKey ?? throw new InvalidOperationException("Notes are locked.");
        // Wiped in place at process exit (SecureMemory.WipeAll) while this save was still due: never seal the notes with
        // the all-zero key — the password could no longer open that file, and anyone could. notes.dat stays as it was.
        if (SecureMemory.IsWiped(key)) throw new InvalidOperationException("Notes are locked.");
        const int Head = 4 + 1 + 16 + 12 + 16;   // magic, version, salt, nonce, tag
        byte[] file = new byte[Head + plainUtf8.Length];
        Magic.CopyTo(file, 0);
        file[Magic.Length] = FormatVersion;
        _sessionSalt.AsSpan(0, 16).CopyTo(file.AsSpan(Magic.Length + 1));
        Span<byte> nonce = file.AsSpan(Magic.Length + 17, 12);
        RandomNumberGenerator.Fill(nonce);
        using (var gcm = new AesGcm(key, 16))
            gcm.Encrypt(nonce, plainUtf8, file.AsSpan(Head), file.AsSpan(Magic.Length + 29, 16));
        return file;
    }

    // Current format: also hands back the derived key + this file's salt, which become the session key (so saves don't
    // re-derive). Legacy AES-CBC: both null. Throws on a wrong key / tampering. Returns the plaintext as a pinned UTF-8
    // buffer the caller zeroes.
    private static byte[] Decrypt(byte[] data, ReadOnlySpan<char> password, out bool legacy, out byte[]? key, out byte[]? salt)
    {
        key = null;
        salt = null;
        if (IsCurrentFormat(data))
        {
            legacy = false;
            int o = Magic.Length + 1;
            byte[] s = data.AsSpan(o, 16).ToArray(); o += 16;
            ReadOnlySpan<byte> nonce = data.AsSpan(o, 12); o += 12;
            ReadOnlySpan<byte> tag = data.AsSpan(o, 16); o += 16;
            ReadOnlySpan<byte> cipher = data.AsSpan(o);

            byte[] k = DeriveKey(password, s);
            byte[] plain = SecureMemory.Alloc(cipher.Length);
            try
            {
                using var gcm = new AesGcm(k, 16);
                gcm.Decrypt(nonce, cipher, tag, plain); // throws on wrong key / tampering
            }
            catch
            {
                SecureMemory.Zero(k);
                SecureMemory.Zero(plain);
                throw;
            }
            key = k;
            salt = s;
            return plain;
        }

        legacy = true;
        return DecryptLegacy(data, password);
    }

    private static bool IsCurrentFormat(byte[] data)
    {
        if (data.Length < Magic.Length + 1 + 16 + 12 + 16) return false;
        for (int i = 0; i < Magic.Length; i++)
            if (data[i] != Magic[i]) return false;
        return data[Magic.Length] == FormatVersion;
    }

    // Migration only (old AES-CBC files are re-encrypted right after the unlock).
    private static byte[] DecryptLegacy(byte[] cipherData, ReadOnlySpan<char> password)
    {
        using Aes aes = Aes.Create();
        // One 48-byte PBKDF2 output split key(32) | IV(16) — byte-identical to the old (now obsolete,
        // SYSLIB0060) Rfc2898DeriveBytes instance's GetBytes(32) then GetBytes(16), so old files still open.
        byte[] derived = SecureMemory.Pbkdf2(password, LegacySalt, 5000, 48);
        try
        {
            aes.Key = derived[..32];
            aes.IV = derived[32..];
        }
        finally { SecureMemory.Zero(derived); }

        using var ms = new MemoryStream(cipherData);
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new StreamReader(cs);
        return SecureMemory.Utf8(reader.ReadToEnd());
    }

    [RelayCommand]
    private void AddNote()
    {
        if (IsLocked) return;
        var note = new NoteItem { Title = "New note " + (Notes.Count + 1) };
        note.PropertyChanged += OnNoteEdited;
        Notes.Add(note);
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
        note.PropertyChanged -= OnNoteEdited;
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
        CancelUnlock();
        CancelPendingSave();
        foreach (var n in Notes) n.PropertyChanged -= OnNoteEdited;
        Notes.Clear();
        FilteredNotes.Clear();
        SearchQuery = string.Empty;
        MasterKey = string.Empty;
        ClearSessionKey();
        _isAuthenticated = false;
        IsLocked = true;
        IsEditing = false;
    }
}
