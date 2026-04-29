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

namespace Echoes.ViewModels;

public class NoteItem : ObservableObject
{
    private string _title = string.Empty;
    public string Title { get => _title; set => SetProperty(ref _title, value); }

    private string _content = string.Empty;
    public string Content { get => _content; set => SetProperty(ref _content, value); }
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
    private readonly string _filePath = Path.Combine(AppContext.BaseDirectory, "notes.dat");
    private readonly byte[] _salt = Encoding.UTF8.GetBytes("Echoes_Fixed_Salt_Unique_2026");

    [ObservableProperty] private ObservableCollection<NoteItem> _notes = new();
    [ObservableProperty] private NoteItem? _selectedNote;
    [ObservableProperty] private bool _isEditing;
    [ObservableProperty] private bool _isLocked = true;
    [ObservableProperty] private string _masterKey = string.Empty;
    [ObservableProperty] private string _errorMessage = string.Empty;

    private bool _isAuthenticated = false;

    [RelayCommand]
    private void Unlock()
    {
        if (string.IsNullOrWhiteSpace(MasterKey))
        {
            ErrorMessage = "Enter a Master Key.";
            return;
        }

        if (!File.Exists(_filePath))
        {
            _isAuthenticated = true;
            IsLocked = false;
            Notes = new ObservableCollection<NoteItem>();
            ErrorMessage = string.Empty;
            SaveNotes();
            return;
        }

        try
        {
            byte[] data = File.ReadAllBytes(_filePath);
            string decrypted = Decrypt(data, MasterKey);
            var package = JsonSerializer.Deserialize(decrypted, NotePackageContext.Default.NotePackage);

            if (package != null && package.AuthTag == "ECHOES_VERIFIED_V1")
            {
                Notes = new ObservableCollection<NoteItem>(package.Notes);
                _isAuthenticated = true;
                IsLocked = false;
                ErrorMessage = string.Empty;
            }
            else
            {
                ErrorMessage = "Decryption failed. Wrong key?";
            }
        }
        catch (Exception ex)
        {
            _isAuthenticated = false;
            ErrorMessage = "Error: " + ex.Message;
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
        using Aes aes = Aes.Create();
        using var pbkdf2 = new Rfc2898DeriveBytes(password, _salt, 5000, HashAlgorithmName.SHA256);
        byte[] key = pbkdf2.GetBytes(32);
        byte[] iv = pbkdf2.GetBytes(16);
        aes.Key = key;
        aes.IV = iv;

        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            byte[] input = Encoding.UTF8.GetBytes(plainText);
            cs.Write(input, 0, input.Length);
        }

        Array.Clear(key, 0, key.Length);
        Array.Clear(iv, 0, iv.Length);
        return ms.ToArray();
    }

    private string Decrypt(byte[] cipherData, string password)
    {
        using Aes aes = Aes.Create();
        using var pbkdf2 = new Rfc2898DeriveBytes(password, _salt, 5000, HashAlgorithmName.SHA256);
        byte[] key = pbkdf2.GetBytes(32);
        byte[] iv = pbkdf2.GetBytes(16);
        aes.Key = key;
        aes.IV = iv;

        using var ms = new MemoryStream(cipherData);
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var reader = new StreamReader(cs);
        string result = reader.ReadToEnd();

        Array.Clear(key, 0, key.Length);
        Array.Clear(iv, 0, iv.Length);
        return result;
    }

    [RelayCommand]
    private void AddNote()
    {
        if (IsLocked) return;
        Notes.Add(new NoteItem { Title = "New Note " + (Notes.Count + 1) });
        SaveNotes();
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
    }

    [RelayCommand]
    private void DeleteNote(NoteItem note)
    {
        if (IsLocked) return;
        Notes.Remove(note);
        SaveNotes();
        if (SelectedNote == note) BackToList();
    }

    [RelayCommand]
    private void LockApp()
    {
        if (!IsLocked && _isAuthenticated) SaveNotes();
        Notes.Clear();
        MasterKey = string.Empty;
        _isAuthenticated = false;
        IsLocked = true;
        IsEditing = false;
    }
}