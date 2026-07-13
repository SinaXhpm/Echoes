using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _hashIdInput = string.Empty;
    [ObservableProperty] private string _hashIdOutput = string.Empty;

    [RelayCommand]
    private void RunHashId()
    {
        try
        {
            ResetError();
            var h = HashIdInput.Trim();
            if (string.IsNullOrEmpty(h)) return;

            var candidates = new List<string>();
            bool isHex = Regex.IsMatch(h, "^[0-9a-fA-F]+$");   // computed once, reused for the branch + charset label

            // Prefixed / structured formats first
            if (h.StartsWith("$2a$") || h.StartsWith("$2b$") || h.StartsWith("$2y$")) candidates.Add("bcrypt");
            else if (h.StartsWith("$1$")) candidates.Add("MD5 crypt (Unix)");
            else if (h.StartsWith("$5$")) candidates.Add("SHA-256 crypt (Unix)");
            else if (h.StartsWith("$6$")) candidates.Add("SHA-512 crypt (Unix)");
            else if (h.StartsWith("$argon2")) candidates.Add("Argon2");
            else if (h.StartsWith("$pbkdf2")) candidates.Add("PBKDF2");
            else if (Regex.IsMatch(h, @"^eyJ[A-Za-z0-9_-]+\.")) candidates.Add("JWT (JSON Web Token)");
            else if (isHex)
            {
                switch (h.Length)
                {
                    case 8: candidates.AddRange(new[] { "CRC-32", "Adler-32" }); break;
                    case 16: candidates.AddRange(new[] { "CRC-64", "MySQL 3.23" }); break;
                    case 32: candidates.AddRange(new[] { "MD5", "MD4", "NTLM", "MD2" }); break;
                    case 40: candidates.AddRange(new[] { "SHA-1", "RIPEMD-160" }); break;
                    case 56: candidates.AddRange(new[] { "SHA-224", "SHA3-224" }); break;
                    case 64: candidates.AddRange(new[] { "SHA-256", "SHA3-256", "BLAKE2s-256" }); break;
                    case 96: candidates.AddRange(new[] { "SHA-384", "SHA3-384" }); break;
                    case 128: candidates.AddRange(new[] { "SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool" }); break;
                    default: candidates.Add($"Unknown hex digest ({h.Length} chars)"); break;
                }
            }
            else if (Regex.IsMatch(h, "^[A-Za-z0-9+/]+={0,2}$") && h.Length % 4 == 0)
                candidates.Add("Base64-encoded data (not a hex hash)");

            if (candidates.Count == 0) candidates.Add("Unrecognized format.");

            var sb = new StringBuilder();
            Row2(sb, "Length", h.Length.ToString());
            Row2(sb, "Charset", isHex ? "hex" : "mixed");
            sb.AppendLine();
            sb.AppendLine("Possible types:");
            foreach (var c in candidates) sb.AppendLine("  • " + c);

            HashIdOutput = sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }
}
