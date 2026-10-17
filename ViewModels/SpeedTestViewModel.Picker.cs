using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// The destination picker: Cloudflare, the curated test-file hosts by region (each a provider in a city), and the
/// user's own saved destinations; the search box filters them by city, country or provider. Nothing is fetched to fill
/// it. (speedtest.net's server list used to be offered too, but near a connection it is that country's ISPs, which
/// measure the domestic network, not the internet.)
/// </summary>
public partial class SpeedTestViewModel
{
    private static readonly string[] CuratedRegions = { "Europe", "Asia", "Americas" };

    private List<SpeedTestDestination> _saved = new();

    /// <summary>A destination was picked or added: the view closes the picker.</summary>
    public event Action? PickDone;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(DestTitle), nameof(DestMeta), nameof(DestCountryCode), nameof(DestHasFlag), nameof(DestTip))]
    private SpeedTestDestination _selectedDestination = SpeedTestDestinations.Cloudflare;

    public string DestTitle => SelectedDestination.Name;
    public string DestMeta => RowMeta(SelectedDestination);
    public string DestCountryCode => SelectedDestination.CountryCode;
    public bool DestHasFlag => SelectedDestination.CountryCode.Length == 2;
    public string DestTip => $"Where the test runs: {SelectedDestination.Name} ({SelectedDestination.Url.Host}). Click to pick another server.";

    partial void OnSelectedDestinationChanged(SpeedTestDestination value)
    {
        if (_loaded) ProfileService.Instance.SetSetting(SpeedTestDestinations.SelectedKey, value.Id);
    }

    [ObservableProperty] private IReadOnlyList<object> _pickItems = Array.Empty<object>();
    [ObservableProperty] private string _pickFilter = "";

    partial void OnPickFilterChanged(string value) => RebuildPickList();

    [RelayCommand]
    private void ClearPickFilter() => PickFilter = "";

    private void LoadDestinations()
    {
        _saved = SpeedTestDestinations.LoadSaved();
        // Rewritten once when it still holds speedtest.net servers an older version kept (LoadSaved drops them).
        if (ProfileService.Instance.GetSetting(SpeedTestDestinations.SavedKey) is { } raw && raw.Contains("\"st:", StringComparison.Ordinal))
            SpeedTestDestinations.SaveSaved(_saved);
        string? id = ProfileService.Instance.GetSetting(SpeedTestDestinations.SelectedKey);
        SelectedDestination = SpeedTestDestinations.FindCurated(id) ?? _saved.FirstOrDefault(d => d.Id == id) ?? SpeedTestDestinations.Cloudflare;
    }

    /// <summary>The picker opened: the list as it is now.</summary>
    public void PickerOpened()
    {
        IsEditing = false;
        RebuildPickList();
    }

    /// <summary>Builds the picker's rows: groups in a fixed order, each filtered by the search text; a group with
    /// nothing to show is left out.</summary>
    internal void RebuildPickList()
    {
        var items = new List<object>();
        string[] words = (PickFilter ?? "").Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        void Group(string title, IEnumerable<SpeedTestDestination> list, bool removable)
        {
            var rows = list.Where(d => Matches(d, words)).Select(d => (object)Row(d, removable)).ToList();
            if (rows.Count == 0) return;
            items.Add(new SpeedPickHeader(title));
            items.AddRange(rows);
        }

        Group(SpeedTestDestinations.AutomaticRegion, new[] { SpeedTestDestinations.Cloudflare }, false);
        Group(SpeedTestDestinations.SavedRegion, _saved, true);
        foreach (string region in CuratedRegions)
            Group(region, SpeedTestDestinations.Curated.Where(d => d.Region == region), false);

        if (items.Count == 0) items.Add(new SpeedPickNote("Nothing matches: try a city, a country or a provider, or add your own."));
        PickItems = items;
    }

    private static bool Matches(SpeedTestDestination d, string[] words)
    {
        if (words.Length == 0) return true;
        string hay = $"{d.Provider} {d.Place} {d.Country} {d.CountryCode} {d.Region} {d.Url.Host}";
        return words.All(w => hay.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    private SpeedPickRow Row(SpeedTestDestination d, bool removable)
        => new(d, d.Id == SelectedDestination.Id, RowMeta(d), Pick, removable ? Remove : null);

    /// <summary>"Germany · download only", "Helsinki, Finland · 3 km · download and upload", "Nearest data center · …".</summary>
    internal static string RowMeta(SpeedTestDestination d)
    {
        string where = d.Kind == SpeedTestKind.Cloudflare && d.Place.Length == 0 && !d.Saved
            ? "Nearest data center"
            : d.Place.Length > 0 && !d.Saved
                ? string.Join(" · ", new[] { d.Country.Length > 0 ? d.Country : d.CountryCode, double.IsNaN(d.DistanceKm) ? "" : Km(d.DistanceKm) }.Where(s => s.Length > 0))
                : SpeedTestDestinations.Where(d);
        var parts = new List<string>(3);
        if (where.Length > 0) parts.Add(where);
        parts.Add(d.Measures);
        if (!d.Secure) parts.Add("HTTP");
        return string.Join(" · ", parts);

        static string Km(double km) => km.ToString(km < 10 ? "0.#" : "0", System.Globalization.CultureInfo.InvariantCulture) + " km";
    }

    private void Pick(SpeedPickRow row)
    {
        if (IsRunning) return;
        SelectedDestination = row.Destination;
        Error = null;
        RebuildPickList();
        PickDone?.Invoke();
    }

    private void Remove(SpeedPickRow row)
    {
        if (IsRunning) return;
        if (_saved.RemoveAll(x => x.Id == row.Destination.Id) == 0) return;
        SpeedTestDestinations.SaveSaved(_saved);
        if (SelectedDestination.Id == row.Destination.Id) SelectedDestination = SpeedTestDestinations.Cloudflare;
        RebuildPickList();
    }

    // ---------- adding a destination ----------

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsListing))]
    private bool _isEditing;

    public bool IsListing => !IsEditing;

    [ObservableProperty] private string _editName = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(EditDetected), nameof(HasEditDetected))] private string _editAddress = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(EditDetected), nameof(HasEditDetected))] private string _editUpload = "";
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasEditError))] private string? _editError;

    public string? EditDetected => SpeedTestDestinations.DescribeAddress(EditAddress, EditUpload);
    public bool HasEditDetected => EditDetected is not null && !HasEditError;
    public bool HasEditError => !string.IsNullOrEmpty(EditError);

    partial void OnEditAddressChanged(string value) => EditError = null;
    partial void OnEditUploadChanged(string value) => EditError = null;
    partial void OnEditErrorChanged(string? value) => OnPropertyChanged(nameof(HasEditDetected));

    [RelayCommand]
    private void AddDestination()
    {
        EditName = EditAddress = EditUpload = "";
        EditError = null;
        IsEditing = true;
    }

    [RelayCommand]
    private void CancelEdit()
    {
        IsEditing = false;
        EditError = null;
    }

    [RelayCommand]
    private void SaveDestination()
    {
        if (_saved.Count(d => d.Id.StartsWith("c:", StringComparison.Ordinal)) >= SpeedTestDestinations.MaxSavedCustom)
        {
            EditError = $"There are {SpeedTestDestinations.MaxSavedCustom} saved destinations already: remove one first.";
            return;
        }
        if (!SpeedTestDestinations.TryCreateCustom(EditName, EditAddress, EditUpload, out var d, out string error))
        {
            EditError = error;
            return;
        }
        _saved.Insert(0, d!);
        SpeedTestDestinations.SaveSaved(_saved);
        IsEditing = false;
        if (!IsRunning) SelectedDestination = d!;
        PickFilter = "";
        RebuildPickList();
        PickDone?.Invoke();
    }
}

/// <summary>A group title in the picker.</summary>
public sealed class SpeedPickHeader(string text)
{
    public string Text { get; } = text;
}

/// <summary>A line in place of the rows (nothing matches the search).</summary>
public sealed class SpeedPickNote(string text, bool isError = false)
{
    public string Text { get; } = text;
    public bool IsError { get; } = isError;
}

/// <summary>One destination in the picker.</summary>
public sealed class SpeedPickRow
{
    internal SpeedPickRow(SpeedTestDestination d, bool selected, string meta, Action<SpeedPickRow> pick, Action<SpeedPickRow>? remove)
    {
        Destination = d;
        IsSelected = selected;
        Meta = meta;
        PickCommand = new RelayCommand(() => pick(this));
        if (remove is not null) RemoveCommand = new RelayCommand(() => remove(this));
    }

    public SpeedTestDestination Destination { get; }
    public string Title => Destination.Name;
    public string Meta { get; }
    public string CountryCode => Destination.CountryCode;
    public bool HasFlag => Destination.CountryCode.Length == 2;
    public bool NoFlag => !HasFlag;
    public bool IsSelected { get; }
    public bool CanRemove => RemoveCommand is not null;
    public IRelayCommand PickCommand { get; }
    public IRelayCommand? RemoveCommand { get; }
    public string Tip => $"{Destination.Name} · {Destination.Url.Host}";
}
