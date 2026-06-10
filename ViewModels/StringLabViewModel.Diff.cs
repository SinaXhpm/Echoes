using System;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Echoes.ViewModels;

public partial class StringLabViewModel
{
    [ObservableProperty] private string _diffLeft = string.Empty;
    [ObservableProperty] private string _diffRight = string.Empty;
    [ObservableProperty] private string _diffOutput = string.Empty;

    [RelayCommand]
    private void RunDiff()
    {
        try
        {
            ResetError();
            var a = DiffLeft.Replace("\r\n", "\n").Split('\n');
            var b = DiffRight.Replace("\r\n", "\n").Split('\n');

            // Longest Common Subsequence (line level)
            int n = a.Length, m = b.Length;
            var lcs = new int[n + 1, m + 1];
            for (int i = n - 1; i >= 0; i--)
                for (int j = m - 1; j >= 0; j--)
                    lcs[i, j] = a[i] == b[j] ? lcs[i + 1, j + 1] + 1 : Math.Max(lcs[i + 1, j], lcs[i, j + 1]);

            var sb = new StringBuilder();
            int added = 0, removed = 0;
            int x = 0, y = 0;
            while (x < n && y < m)
            {
                if (a[x] == b[y]) { sb.AppendLine("  " + a[x]); x++; y++; }
                else if (lcs[x + 1, y] >= lcs[x, y + 1]) { sb.AppendLine("- " + a[x]); x++; removed++; }
                else { sb.AppendLine("+ " + b[y]); y++; added++; }
            }
            while (x < n) { sb.AppendLine("- " + a[x]); x++; removed++; }
            while (y < m) { sb.AppendLine("+ " + b[y]); y++; added++; }

            string summary = added == 0 && removed == 0
                ? "# Identical"
                : $"# +{added} added, -{removed} removed";

            DiffOutput = summary + Environment.NewLine + Environment.NewLine + sb.ToString().TrimEnd();
        }
        catch (Exception ex) { ErrorMessage = ex.Message; }
    }
}
