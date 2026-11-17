using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Echoes.ViewModels;

// The resolver list editor: one row per resolver in the order they are asked, a box to add one (checked as it is added),
// remove, move up. The list stays kept as text, one resolver per line (DnsServersText / CompareServersText, saved under
// the same keys as when it was typed into a box): every edit rewrites that text and the rows are made again from it, so
// the presets, the runs and the saved settings read it exactly as before.
public partial class DnsViewModel
{
    /// <summary>The current mode's list, a row per line (a line that isn't a resolver shows why).</summary>
    public ObservableCollection<ResolverRow> ResolverRows { get; } = new();

    [ObservableProperty] private bool _hasResolverRows;

    /// <summary>The add box: one resolver, or several separated by spaces or commas.</summary>
    [ObservableProperty] private string _newResolverText = "";

    /// <summary>Why the add box's text wasn't added (not a resolver, already in the list). One line.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasNewResolverError))]
    private string _newResolverError = "";

    public bool HasNewResolverError => NewResolverError.Length > 0;

    // the add box's text, kept like any input until it is added
    private const string ResolverDraftKey = "dns.resolverDraft";

    partial void OnNewResolverTextChanged(string value)
    {
        NewResolverError = "";   // it was about the text before this edit
        if (_loaded) Store.Profile.SetSetting(ResolverDraftKey, value);
    }

    /// <summary>Resolvers were added from the box: at the end of the list, where the view scrolls.</summary>
    public event Action? ResolverAdded;

    private void RebuildResolverRows()
    {
        NewResolverError = "";   // about the list as it was
        ResolverRows.Clear();
        // the same resolver twice is one row (ParseList asks it once anyway); the next edit writes it once
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in SplitLines(ResolverText))
        {
            var row = new ResolverRow(line, isFirst: ResolverRows.Count == 0);
            if (seen.Add(row.Canonical)) ResolverRows.Add(row);
        }
        HasResolverRows = ResolverRows.Count > 0;
    }

    private void SetResolverLines(IEnumerable<string> lines) => ResolverText = string.Join(Environment.NewLine, lines);

    /// <summary>Adds what the add box holds, each in its canonical form; what isn't added (not a resolver, already listed)
    /// stays in the box with the reason under it.</summary>
    [RelayCommand]
    private void AddResolver()
    {
        if (IsWorking) return;
        string[] parts = NewResolverText.Split(new[] { ' ', '\t', '\r', '\n', ',' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return;
        var lines = ResolverRows.Select(r => r.Line).ToList();
        var present = new HashSet<string>(ResolverRows.Select(r => r.Canonical), StringComparer.OrdinalIgnoreCase);
        var kept = new List<string>();
        string error = "";
        foreach (string part in parts)
        {
            if (!ResolverSpec.TryParse(part, out var spec, out string why))
            {
                kept.Add(part);
                if (error.Length == 0) error = $"{Clip(part)}: {why}";
            }
            else if (!present.Add(spec.Text))
            {
                kept.Add(part);
                if (error.Length == 0) error = $"{spec.Short} is in the list already";
            }
            else lines.Add(spec.Text);
        }
        if (lines.Count > ResolverRows.Count)
        {
            SetResolverLines(lines);
            ResolverAdded?.Invoke();
        }
        NewResolverText = string.Join(" ", kept);
        NewResolverError = error;   // after the text and the list: a change of either clears it

        static string Clip(string s) => s.Length > 40 ? s[..40] + "…" : s;
    }

    [RelayCommand]
    private void RemoveResolver(ResolverRow? row)
    {
        if (row is null || IsWorking) return;
        SetResolverLines(ResolverRows.Where(r => r != row).Select(r => r.Line));
    }

    /// <summary>One place earlier: the email check uses the first resolver that answers.</summary>
    [RelayCommand]
    private void MoveResolverUp(ResolverRow? row)
    {
        if (row is null || IsWorking) return;
        var lines = ResolverRows.Select(r => r.Line).ToList();
        int i = ResolverRows.IndexOf(row);
        if (i <= 0) return;
        (lines[i - 1], lines[i]) = (lines[i], lines[i - 1]);
        SetResolverLines(lines);
    }
}
