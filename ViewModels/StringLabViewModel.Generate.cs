using System;
using System.Security.Cryptography;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _generateOutput = string.Empty;
    [ObservableProperty] private int _generateLength = 24;
    [ObservableProperty] private int _generateCount = 5;

    private const string PwUpper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string PwLower = "abcdefghijkmnopqrstuvwxyz";
    private const string PwDigit = "23456789";
    private const string PwSymbol = "!@#$%^&*-_=+?";

    [RelayCommand]
    private void Generate(string type)
    {
        try
        {
            ResetError();
            int count = Math.Clamp(GenerateCount, 1, 100);
            var sb = new StringBuilder();
            for (int i = 0; i < count; i++)
                sb.AppendLine(GenerateOne(type));
            GenerateOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }

    private string GenerateOne(string type)
    {
        int len = Math.Clamp(GenerateLength, 1, 512);
        return type switch
        {
            "uuid" => Guid.NewGuid().ToString(),
            "guidn" => Guid.NewGuid().ToString("N"),
            "password" => RandomFrom(PwUpper + PwLower + PwDigit + PwSymbol, len),
            "alnum" => RandomFrom(PwUpper + PwLower + PwDigit, len),
            "hex" => Convert.ToHexString(RandomNumberGenerator.GetBytes(len)).ToLowerInvariant(),
            "base64" => Convert.ToBase64String(RandomNumberGenerator.GetBytes(len)),
            "pin" => RandomFrom("0123456789", len),
            _ => Guid.NewGuid().ToString()
        };
    }

    private static string RandomFrom(string charset, int length)
    {
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++)
            sb.Append(charset[RandomNumberGenerator.GetInt32(charset.Length)]);
        return sb.ToString();
    }
}
