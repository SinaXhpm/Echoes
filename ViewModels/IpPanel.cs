using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>
/// A tool's actions on the IP addresses its results show: the inline WHOIS under a row (who holds the address), and
/// handing an address to WHOIS or IP Info through <see cref="IToolLinks"/>. The lookups in flight belong to the tool's
/// current search and are cancelled together when it starts a new one.
/// </summary>
public sealed class IpLinkScope
{
    /// <summary>The most addresses one row lists (an SPF record or a list of mail servers can hold dozens).</summary>
    public const int MaxPerRow = 8;

    private CancellationTokenSource _cts = new();

    public IpLinkScope(IToolLinks? links) => Links = links;

    /// <summary>Where WHOIS / IP Info hand-offs go; null hides those buttons.</summary>
    public IToolLinks? Links { get; }

    internal CancellationToken Token => _cts.Token;

    /// <summary>Stops the inline WHOIS lookups still running (a new search started): an address asks again when its
    /// panel is opened next. UI thread.</summary>
    public void CancelLookups()
    {
        var old = _cts;
        _cts = new CancellationTokenSource();
        old.Cancel();
        old.Dispose();
    }

    /// <summary>The panel for <paramref name="addresses"/> (an address, or a range "a.b.c.d/len" as an SPF record has
    /// it), each once and at most <see cref="MaxPerRow"/>; null when there are none. Any thread.</summary>
    public IpPanel? For(IEnumerable<string> addresses)
    {
        var items = new List<IpItem>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int more = 0;
        foreach (string entry in addresses)
        {
            int slash = entry.IndexOf('/');
            string text = slash > 0 ? entry[..slash] : entry;
            // IPAddress.TryParse also takes "13335" or "1.2" as IPv4: only a dotted quad is an address here
            if (!IPAddress.TryParse(text, out var ip) || (ip.AddressFamily == AddressFamily.InterNetwork && !HostExtractor.IsStrictIPv4(text)))
                continue;
            string address = ip.ToString();
            string label = slash > 0 ? address + entry[slash..] : address;
            if (!seen.Add(label)) continue;
            if (items.Count == MaxPerRow) { more++; continue; }
            items.Add(new IpItem(ip, label, this));
        }
        return items.Count == 0 ? null : new IpPanel(items, more);
    }
}

/// <summary>The addresses one result row shows, opened under the row by the toggle beside it.</summary>
public sealed partial class IpPanel : ObservableObject
{
    internal IpPanel(IReadOnlyList<IpItem> items, int more)
    {
        Items = items;
        MoreText = more == 0 ? "" : more == 1 ? "+1 more address in this row" : $"+{more} more addresses in this row";
    }

    public IReadOnlyList<IpItem> Items { get; }
    public string MoreText { get; }
    public bool HasMore => MoreText.Length > 0;

    [ObservableProperty] private bool _isOpen;

    /// <summary>Opens the panel, asking who holds each address (once a session), or closes it.</summary>
    [RelayCommand]
    private void Toggle()
    {
        IsOpen = !IsOpen;
        if (IsOpen)
            foreach (var item in Items) item.Load();
    }
}

/// <summary>One address under a row: who holds it (asked when its panel opens), and WHOIS / IP Info for it.</summary>
public sealed partial class IpItem : ObservableObject
{
    private readonly IPAddress _ip;
    private readonly IpLinkScope _scope;
    private bool _loading, _done;

    internal IpItem(IPAddress ip, string label, IpLinkScope scope)
    {
        _ip = ip;
        _scope = scope;
        Address = ip.ToString();
        Label = label;
    }

    /// <summary>The address WHOIS / IP Info get: "192.0.2.0" for the range 192.0.2.0/24.</summary>
    public string Address { get; }
    /// <summary>As the row has it: the address, or its range.</summary>
    public string Label { get; }
    /// <summary>WHOIS and IP Info have something to say: not about a private or other special-purpose address.</summary>
    public bool CanSend => _scope.Links != null && Rdap.SpecialPurpose(_ip) is null;

    /// <summary>"looking up…", what the address is (private, loopback …), or why nothing came back.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasStatus))]
    private string _status = "";
    public bool HasStatus => Status.Length > 0;
    [ObservableProperty] private bool _isError;
    /// <summary>Holder, network, country, range, ASN and abuse contact: the ones its registry publishes.</summary>
    [ObservableProperty] private IReadOnlyList<IpFact> _facts = Array.Empty<IpFact>();

    [RelayCommand]
    private void Whois() => _scope.Links?.Whois(Address);

    [RelayCommand]
    private void IpInfo() => _scope.Links?.LookUpIp(Address);

    [RelayCommand]
    private Task Copy() => ClipboardHelper.SetTextAsync(Label);

    /// <summary>Asks who holds the address, unless that is known or being asked already. UI thread.</summary>
    internal void Load()
    {
        if (_loading || _done) return;
        if (Rdap.Known(_ip) is { } known) { Show(known); return; }
        _ = LoadAsync();
    }

    private async Task LoadAsync()
    {
        _loading = true;
        IsError = false;
        Status = "looking up…";
        try { Show(await Rdap.LookUpIpAsync(_ip, _scope.Token)); }
        catch (OperationCanceledException) { Status = "stopped: a new search started (open it again to retry)"; }
        catch (Exception ex)
        {
            CrashLog.Write("IpItem.Load", ex);
            IsError = true;
            Status = "No WHOIS: " + ex.Message;
        }
        finally { _loading = false; }
    }

    private void Show(IpWhois w)
    {
        var facts = new List<IpFact>();
        void Add(string key, string value) { if (value.Length > 0) facts.Add(new IpFact(key, value)); }
        Add("Org", w.Org);
        Add("Network", w.Network);
        Add("Country", w.Country);
        Add("Range", w.Range);
        Add("ASN", w.Asn);
        Add("Abuse", w.Abuse);
        Facts = facts;
        IsError = w.Error != null;
        Status = w.Error ?? w.Note;
        _done = w.Error == null;
    }
}

/// <summary>One line of an address's WHOIS: "Org Cloudflare, Inc.".</summary>
public sealed record IpFact(string Key, string Value);
