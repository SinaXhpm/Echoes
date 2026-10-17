using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

// Add a site: POST /zones {"name", "account": {"id"}, "type": "full"} (Zone → Zone : Edit on all zones of the account).
// The account comes from the zones already loaded; with none, GET /accounts (Account → Account Settings : Read). The new
// zone starts "pending": the page then shows the two name servers to set at the registrar. Zones are never deleted here.
public partial class CloudflareViewModel
{
    [ObservableProperty] private bool _isAddZoneOpen;
    [ObservableProperty] private string _newZoneName = string.Empty;
    [ObservableProperty] private CfOption? _newZoneAccount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAddZoneError))]
    private string _addZoneError = string.Empty;

    [ObservableProperty] private bool _isAddingZone;
    [ObservableProperty] private bool _isLoadingAccounts;

    /// <summary>The zone just added (the page shows its name servers); null while the form is showing.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsAddZoneForm), nameof(IsAddZoneDone))]
    private CfZone? _addedZone;

    public ObservableCollection<CfOption> Accounts { get; } = new();
    public ObservableCollection<CfField> AddedZoneFields { get; } = new();
    public bool HasAddZoneError => AddZoneError.Length > 0;
    public bool IsAddZoneForm => AddedZone is null;
    public bool IsAddZoneDone => AddedZone is not null;
    /// <summary>More than one account: the form asks which one.</summary>
    public bool ShowAccountPicker => Accounts.Count > 1;

    partial void OnNewZoneNameChanged(string value) => AddZoneError = string.Empty;

    [RelayCommand]
    private async Task OpenAddZone()
    {
        if (IsLocked || SelectedProfile?.HasCredentials != true) return;
        NewZoneName = string.Empty;
        AddZoneError = string.Empty;
        AddedZone = null;
        AddedZoneFields.Clear();
        IsAddZoneOpen = true;

        // The accounts the loaded zones belong to; asked for only when there are none.
        Accounts.Clear();
        foreach (var g in Zones.Where(z => z.AccountId.Length > 0).GroupBy(z => z.AccountId))
            Accounts.Add(new CfOption(g.Key, g.First().AccountName.Length > 0 ? g.First().AccountName : g.Key));
        if (Accounts.Count == 0) await LoadAccountsAsync();
        NewZoneAccount = Accounts.FirstOrDefault(a => a.Value == SelectedZone?.AccountId) ?? Accounts.FirstOrDefault();
        OnPropertyChanged(nameof(ShowAccountPicker));
    }

    private async Task LoadAccountsAsync()
    {
        var api = Api(out string error);
        if (api is null) { AddZoneError = error; return; }
        int session = _sessionGen;
        IsLoadingAccounts = true;
        CfListResponse r;
        try { r = await api.GetAllAsync("/accounts", 50, CfPermission.AccountRead, _sessionCts.Token, maxPages: 5); }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) IsLoadingAccounts = false;
        }
        if (session != _sessionGen) return;
        if (!r.Success)
        {
            AddZoneError = "Couldn't find your Cloudflare account: " + r.Error;
            return;
        }
        foreach (var a in r.Items)
        {
            string id = CfJson.Str(a["id"]);
            if (!CloudflareApi.IsId(id)) continue;
            string name = CfJson.Str(a["name"]);
            Accounts.Add(new CfOption(id.ToLowerInvariant(), name.Length > 0 ? name : id));
        }
        if (Accounts.Count == 0) AddZoneError = "This token can't see any account to add the site to.";
    }

    [RelayCommand]
    private void CloseAddZone()
    {
        IsAddZoneOpen = false;
        var added = AddedZone;
        AddedZone = null;
        // the new zone opens once the page closes (its records load, the pending note shows the name servers again)
        if (added != null && Zones.FirstOrDefault(z => z.Id == added.Id) is { } z) SelectedZone = z;
    }

    [RelayCommand]
    private async Task AddZone()
    {
        if (IsAddingZone || IsLocked) return;
        string name = CloudflareBackup.NormName(NewZoneName);
        // a pasted URL: keep its host
        if ((name.StartsWith("http://", StringComparison.Ordinal) || name.StartsWith("https://", StringComparison.Ordinal))
            && Uri.TryCreate(name, UriKind.Absolute, out var url))
            name = CloudflareBackup.NormName(url.Host);
        if (name.StartsWith("www.", StringComparison.Ordinal)) name = name[4..];
        if (!CloudflareBackup.IsDnsName(name, wildcard: false) || !name.Contains('.'))
        {
            AddZoneError = "Enter the domain only, like example.com (no www, no http://).";
            return;
        }
        if (Zones.Any(z => string.Equals(z.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            AddZoneError = $"{name} is already in this account.";
            return;
        }
        var api = Api(out string error);
        if (api is null) { AddZoneError = error; return; }
        int session = _sessionGen;
        IsAddingZone = true;
        AddZoneError = string.Empty;
        var body = new JsonObject { ["name"] = name, ["type"] = "full" };
        if (NewZoneAccount is { } acct && CloudflareApi.IsId(acct.Value)) body["account"] = new JsonObject { ["id"] = acct.Value };
        CfResponse r;
        try { r = await api.PostAsync("/zones", body, CfPermission.ZoneCreate, _sessionCts.Token); }
        catch (OperationCanceledException) { return; }
        finally
        {
            if (session == _sessionGen) IsAddingZone = false;
        }
        if (session != _sessionGen) return;
        if (!r.Success || CfZone.FromApi(r.Result) is not { } zone)
        {
            AddZoneError = r.Success ? "Cloudflare answered without the new zone." : r.Error;
            SetError($"{name} wasn't added: {AddZoneError}");
            return;
        }

        // Into the picker, in order; it opens when this page closes.
        int i = 0;
        while (i < Zones.Count && string.Compare(Zones[i].Name, zone.Name, StringComparison.OrdinalIgnoreCase) < 0) i++;
        Zones.Insert(i, zone);
        OnPropertyChanged(nameof(AccountSummary));
        AddedZoneFields.Clear();
        for (int n = 0; n < zone.NameServers.Count; n++)
            AddedZoneFields.Add(new CfField($"Name server {n + 1}", zone.NameServers[n]));
        AddedZone = zone;
        SetStatus($"{zone.Name} was added. Set its name servers at your registrar to activate it.");
    }
}
