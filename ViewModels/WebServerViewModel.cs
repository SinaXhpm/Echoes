using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>Row shown in the shared-files list; wraps a server <see cref="SharedItem"/> + its live stats.</summary>
public sealed partial class SharedFileRow : ObservableObject
{
    public required SharedItem Item { get; init; }
    public string Name => Item.Name;
    public string SizeText => Item.Size > 0 ? FileHttpServer.HumanSize(Item.Size) : "—";

    [ObservableProperty] private int _downloads;
    [ObservableProperty] private long _bytesServed;
    public bool HasDownloads => Downloads > 0;

    public void AddDownload(long bytes, bool complete)
    {
        if (complete) Downloads++;
        BytesServed += bytes;
        OnPropertyChanged(nameof(HasDownloads));
    }

    public void ResetStats()
    {
        Downloads = 0;
        BytesServed = 0;
        OnPropertyChanged(nameof(HasDownloads));
    }

    // ---- the direct link (/f/{token}/{name}): set while the server runs, on the address the page's link uses ----

    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasLink))] private string _linkUrl = string.Empty;
    public bool HasLink => LinkUrl.Length > 0;
    [ObservableProperty] private bool _linkCopied;

    // The same link without the file name, for the QR code: the server ignores the name (and sends it with the file), and
    // an escaped long or Persian name made the code too dense to scan, or longer than a QR code holds.
    private string _qrLink = string.Empty;
    private Bitmap? _qr;
    /// <summary>The link's QR code, made the first time the row's link panel shows it.</summary>
    public Bitmap? Qr => _qr ??= _qrLink.Length > 0 ? WebServerViewModel.BuildQr(_qrLink) : null;

    /// <summary>Points the direct link at the server at <paramref name="baseUrl"/> ("https://192.168.1.5:8443/"), or
    /// removes it (empty: the server is off).</summary>
    internal void SetLink(string baseUrl)
    {
        _qrLink = baseUrl.Length > 0 ? baseUrl + "f/" + Item.LinkToken : string.Empty;
        LinkUrl = _qrLink.Length > 0 ? _qrLink + "/" + Uri.EscapeDataString(Item.Name) : string.Empty;
    }

    partial void OnLinkUrlChanged(string value)
    {
        var old = _qr;
        _qr = null;
        OnPropertyChanged(nameof(Qr));
        old?.Dispose();
    }

    // The link panel's Copy: "Copied" on the button for a moment.
    [RelayCommand]
    private async Task CopyLink()
    {
        if (!HasLink) return;
        await ClipboardHelper.SetTextAsync(LinkUrl);
        LinkCopied = true;
        await Task.Delay(1500);
        LinkCopied = false;
    }
}

/// <summary>One entry in the "how to listen" dropdown. <see cref="Kind"/> is "all" | "loopback" | "iface".</summary>
public sealed record BindOption(string Label, IPAddress Address, string Kind);

/// <summary>
/// The Web Server tool. "Share &amp; chat" (this file and WebServerViewModel.Hub / .Chat / .Inbox): a two-way hub for
/// devices on the same network that can't reach each other otherwise — chat, files from the browser to this device,
/// and files this device shares — over HTTPS by default, opened with a PIN (or the QR / link that carries it), on a
/// managed <see cref="ShareHub"/> that works on desktop and in the Android sandbox without admin / root. "Catch
/// requests" (WebServerViewModel.Catcher.cs) is the webhook inspector.
/// </summary>
public partial class WebServerViewModel : ObservableObject
{
    [ObservableProperty] private int _port = 8080;
    [ObservableProperty] private int _maxConnections = DefaultMaxConnections;   // concurrent-connection cap
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "Start, then open the link on the other device.";
    [ObservableProperty] private bool _statusIsError;
    [ObservableProperty] private string _log = string.Empty;

    private const int DefaultMaxConnections = 64;

    // How the server binds: all interfaces (LAN-visible, default), loopback only, or one specific IP.
    public ObservableCollection<BindOption> BindOptions { get; } = new();
    [ObservableProperty] private BindOption? _selectedBind;
    private bool _rebuildingBinds;

    // QR of the selected share link — scan it with a phone's camera to open the page (logged in: it carries the PIN).
    [ObservableProperty] private string? _selectedShareUrl;
    [ObservableProperty] private Bitmap? _qrImage;

    // Live stats (shown on the Log tab).
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private long _totalConnections;
    [ObservableProperty] private long _totalDownloads;
    [ObservableProperty] private string _bytesSentText = "0 B";
    [ObservableProperty] private string _bytesReceivedText = "0 B";
    [ObservableProperty] private int _clientCount;

    public ObservableCollection<SharedFileRow> Files { get; } = new();
    public ObservableCollection<string> Addresses { get; } = new();

    public bool HasFiles => Files.Count > 0;

    // Thread-safe source of truth the server reads from connection threads.
    private readonly object _itemsLock = new();
    private readonly List<SharedItem> _items = new();

    // The endpoint the live listener ACTUALLY bound (captured at START). While running, the shown
    // URLs/QR come from these, never from the editable settings.
    private IPAddress? _activeBind;
    private int _activePort;

    // Hub callbacks fire on connection threads — possibly thousands per second under a LAN flood.
    // They only enqueue; a 250 ms UI timer (running while live) drains the queues and polls the
    // counters, so the UI cost is flat whatever the load (one UI post per event could swamp it).
    private readonly ConcurrentQueue<string> _pendingLog = new();
    private readonly ConcurrentQueue<(string Id, long Bytes, bool Complete)> _pendingDownloads = new();
    private PacedTimer? _uiTimer;
    private const int MaxPendingLog = 200;   // the TextBox keeps only ~8000 chars anyway

    private IReadOnlyList<SharedItem> SnapshotItems()
    {
        lock (_itemsLock) return _items.ToArray();
    }

    public WebServerViewModel()
    {
        RebuildBindOptions();
        RestoreShareSettings();
        InitCatcher();   // the "Catch requests" mode (WebServerViewModel.Catcher.cs)
        InitInbox();     // received files (WebServerViewModel.Inbox.cs)
    }

    // --- bind-interface selection ---

    // Rebuild the "how to listen" dropdown: All interfaces (dual-stack) + Localhost + one row per live IPv4.
    // Preserves the current pick if it still exists, else defaults to All.
    private void RebuildBindOptions()
    {
        string? prevKind = SelectedBind?.Kind;
        string? prevAddr = SelectedBind?.Address.ToString();

        var list = new List<BindOption>
        {
            new("All interfaces (IPv4 + IPv6)", IPAddress.IPv6Any, "all"),
            new("This device only (127.0.0.1)", IPAddress.Loopback, "loopback"),
        };
        foreach (var (name, address) in NicSnapshot.UpIPv4())
            list.Add(new BindOption($"{address}  ({name})", address, "iface"));

        _rebuildingBinds = true;
        BindOptions.Clear();
        foreach (var o in list) BindOptions.Add(o);
        SelectedBind = BindOptions.FirstOrDefault(o => o.Kind == prevKind && o.Address.ToString() == prevAddr)
                       // a picked interface that went away (DHCP, Wi-Fi off): the narrowest choice, never all interfaces
                       ?? (prevKind == "iface" ? BindOptions.FirstOrDefault(o => o.Kind == "loopback") : null)
                       ?? BindOptions.FirstOrDefault(o => o.Kind == "all")
                       ?? BindOptions.FirstOrDefault();
        _rebuildingBinds = false;
    }

    /// <summary>The share picker's dropdown opened: interfaces come and go (VPN, Wi-Fi).</summary>
    public void RebuildShareBinds()
    {
        if (IsRunning || IsStarting) return;
        RebuildBindOptions();
    }

    partial void OnSelectedBindChanged(BindOption? value)
    {
        if (_rebuildingBinds) return;
        if (!_restoringShare && value is not null)
            ProfileService.Instance.SetSetting(KShareBind, value.Kind == "iface" ? value.Address.ToString() : value.Kind);
        RefreshAddresses();
    }

    // --- remembered share settings: each saved when it changes. The PIN and the certificate only sealed (SecretProtector
    // "enc2:"). The shared files are not kept: picks from a phone's file picker only last for the session, and a stale
    // path list would share the wrong files.

    private const string KSharePort = "webserver.port", KShareMaxConn = "webserver.maxConn", KShareBind = "webserver.bind",
        KPlainHttp = "webserver.plainHttp", KNoPin = "webserver.noPin", KPin = "webserver.pin", KSubTab = "webserver.subTab";
    // the old Basic-auth settings, replaced by the PIN
    private static readonly string[] RetiredKeys = { "webserver.auth", "webserver.user", "webserver.pass" };
    private bool _restoringShare;

    private void RestoreShareSettings()
    {
        var p = ProfileService.Instance;
        _restoringShare = true;
        try
        {
            int port = p.GetInt(KSharePort, 8080);
            Port = port is >= 1 and <= 65535 ? port : 8080;
            MaxConnections = Math.Clamp(p.GetInt(KShareMaxConn, DefaultMaxConnections), 4, 512);
            HttpsOn = !p.GetBool(KPlainHttp);
            PinOn = !p.GetBool(KNoPin);
            SubTabIndex = Math.Clamp(p.GetInt(KSubTab, 0), 0, 2);
            RestorePin(p);
            // a saved interface that isn't up now: this device only (the saved pick stays for the next run)
            if (p.GetSetting(KShareBind) is { Length: > 0 } want
                && (BindOptions.FirstOrDefault(o => o.Kind != "iface" ? o.Kind == want : o.Address.ToString() == want)
                    ?? (IPAddress.TryParse(want, out _) ? BindOptions.FirstOrDefault(o => o.Kind == "loopback") : null)) is { } saved)
            {
                _rebuildingBinds = true;   // as in RebuildBindOptions: the addresses are listed when the page shows
                SelectedBind = saved;
                _rebuildingBinds = false;
            }
        }
        finally { _restoringShare = false; }
        // The password of the old "Require password" switch: the PIN replaced it (on by default), so the sealed
        // password isn't kept around unused.
        foreach (var k in RetiredKeys) if (p.GetSetting(k) is not null) p.Remove(k);
    }

    partial void OnPortChanged(int value)
    {
        if (!_restoringShare && value is >= 1 and <= 65535)
            ProfileService.Instance.SetSetting(KSharePort, value.ToString(CultureInfo.InvariantCulture));
    }

    partial void OnMaxConnectionsChanged(int value)
    {
        if (!_restoringShare && value is >= 4 and <= 512)
            ProfileService.Instance.SetSetting(KShareMaxConn, value.ToString(CultureInfo.InvariantCulture));
    }

    // --- QR of the selected share link ---

    partial void OnSelectedShareUrlChanged(string? value) => UpdateShareLink();

    // Renders a share URL to a crisp black/white QR bitmap (pure managed — see Helpers/QrCode.cs).
    internal static Bitmap? BuildQr(string text)
    {
        bool[,]? m = QrCode.Encode(text);
        if (m is null) return null;
        int n = m.GetLength(0);
        const int scale = 6, quiet = 3;
        int dim = (n + quiet * 2) * scale;
        var wb = new WriteableBitmap(new Avalonia.PixelSize(dim, dim), new Avalonia.Vector(96, 96),
            Avalonia.Platform.PixelFormat.Bgra8888, Avalonia.Platform.AlphaFormat.Opaque);
        using (var fb = wb.Lock())
        {
            int stride = fb.RowBytes;
            var row = new byte[stride];
            for (int y = 0; y < dim; y++)
            {
                int my = y / scale - quiet;
                for (int x = 0; x < dim; x++)
                {
                    int mx = x / scale - quiet;
                    bool dark = mx >= 0 && mx < n && my >= 0 && my < n && m[my, mx];
                    byte v = dark ? (byte)0 : (byte)255;
                    int off = x * 4;
                    row[off] = v; row[off + 1] = v; row[off + 2] = v; row[off + 3] = 255;
                }
                Marshal.Copy(row, 0, IntPtr.Add(fb.Address, y * stride), stride);
            }
        }
        return wb;
    }

    // --- shared files (this device → browsers) ---

    /// <summary>Called from the view after the file picker resolves each file. Returns the shared item. A picker batch
    /// passes notify: false and calls <see cref="SharedFilesAdded"/> once: each notice sends the whole list to every
    /// browser (300 files one by one were ~4 MB per page, which dropped them as not reading).</summary>
    public SharedItem AddSharedFile(string name, long size, Func<Task<Stream>> open, DateTime? lastModifiedUtc = null, bool notify = true)
    {
        var item = new SharedItem
        {
            Id = Guid.NewGuid().ToString("N")[..10],
            Name = name,
            Size = size,
            ContentType = FileHttpServer.GuessContentType(name),
            Open = open,
            LastModifiedUtc = lastModifiedUtc,
        };
        lock (_itemsLock) _items.Add(item);
        var row = new SharedFileRow { Item = item };
        row.SetLink(FileLinkBase);
        Files.Add(row);
        OnPropertyChanged(nameof(HasFiles));
        if (notify) _hub?.NotifyFilesChanged();
        return item;
    }

    public void SharedFilesAdded() => _hub?.NotifyFilesChanged();

    [RelayCommand]
    private void RemoveFile(SharedFileRow? row)
    {
        if (row is null) return;
        lock (_itemsLock) _items.Remove(row.Item);
        Files.Remove(row);
        OnPropertyChanged(nameof(HasFiles));
        _hub?.NotifyFilesChanged();
    }

    [RelayCommand]
    private void ClearFiles()
    {
        if (Files.Count == 0) return;
        lock (_itemsLock) _items.Clear();
        Files.Clear();
        OnPropertyChanged(nameof(HasFiles));
        _hub?.NotifyFilesChanged();
    }

    [RelayCommand]
    private void ToggleServer()
    {
        if (IsStarting) return;
        if (IsRunning) StopInternal();
        else _ = StartAsync();
    }

    /// <summary>Stop both servers (share hub + request catcher) on app shutdown (releases the sockets + background guard).</summary>
    public void StopServer()
    {
        StopInternal();
        StopCatcher();
    }

    [RelayCommand]
    private void RefreshAddresses()
    {
        // the catcher's picker / URLs too (interfaces may have changed); a live catcher keeps what it bound
        if (IsCatchMode)
        {
            if (!IsCatching) RebuildCatchBinds();
            else RefreshCatchUrls();
        }

        // While live, describe the ACTUAL listener and leave SelectedBind alone: a rebuild could
        // re-point it (e.g. to "all" when the picked NIC vanished) and advertise a wrong URL/QR.
        IPAddress? live = IsRunning ? _activeBind : null;
        if (live is null && !IsStarting) RebuildBindOptions();     // interfaces/IPs may have changed since last time
        // Read the QR target before clearing: the link picker binds it two-way and writes null back when
        // Clear() resets the list, so the check below always fell back to the first URL on every refresh.
        string? picked = SelectedShareUrl;
        Addresses.Clear();

        int port = live is null ? Port : _activePort;
        string scheme = (IsRunning ? IsHttpsActive : HttpsOn) ? "https" : "http";
        string P(IPAddress a) => $"{scheme}://{(a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "[" + a + "]" : a.ToString())}:{port.ToString(CultureInfo.InvariantCulture)}/";
        string kind = live is null ? SelectedBind?.Kind ?? "all"
            : live.Equals(IPAddress.Any) || live.Equals(IPAddress.IPv6Any) ? "all"
            : IPAddress.IsLoopback(live) ? "loopback" : "iface";
        IPAddress? ifaceAddr = live ?? SelectedBind?.Address;
        if (kind == "loopback")
        {
            Addresses.Add(P(IPAddress.Loopback));
        }
        else if (kind == "iface" && ifaceAddr is not null)
        {
            Addresses.Add(P(ifaceAddr));
        }
        else // all interfaces → list every reachable LAN IPv4 so any of them works
        {
            foreach (var (_, address) in NicSnapshot.UpIPv4())
                Addresses.Add(P(address));
            if (Addresses.Count == 0) Addresses.Add(P(IPAddress.Loopback));
        }

        // keep the current QR target if it survived the refresh, else point at the first address
        SelectedShareUrl = picked is not null && Addresses.Contains(picked) ? picked : Addresses.FirstOrDefault();
    }

    [RelayCommand]
    private async Task CopyAddress(string? url)
    {
        if (!string.IsNullOrEmpty(url)) await ClipboardHelper.SetTextAsync(LinkFor(url));
    }

    [RelayCommand]
    private void OpenAddress(string? url) => LinkHelper.Open(string.IsNullOrEmpty(url) ? null : LinkFor(url));

    private void ResetStats()
    {
        ActiveConnections = 0;
        TotalConnections = 0;
        TotalDownloads = 0;
        ClientCount = 0;
        BytesSentText = "0 B";
        BytesReceivedText = "0 B";
        foreach (var r in Files) r.ResetStats();
    }

    private void AppendLog(string line)
    {
        _pendingLog.Enqueue($"[{DateTime.Now:HH:mm:ss}] {line}");
        while (_pendingLog.Count > MaxPendingLog && _pendingLog.TryDequeue(out _)) { }   // flood: keep the newest
    }

    [RelayCommand]
    private void ClearLog() => Log = string.Empty;

    // UI thread: drain queued log lines / downloads / chat / uploads into bound state and poll the live counters.
    // True while anything moves: something queued, or the hub's counters changed (the paced timer keeps its fast interval).
    private bool FlushUi()
    {
        bool queued = !_pendingLog.IsEmpty || !_pendingDownloads.IsEmpty || !_pendingChat.IsEmpty || !_pendingUploads.IsEmpty;
        if (!_pendingLog.IsEmpty)
        {
            var batch = new List<string>();
            while (_pendingLog.TryDequeue(out var l)) batch.Add(l);
            var sb = new StringBuilder();
            for (int i = batch.Count - 1; i >= 0; i--) sb.Append(batch[i]).Append('\n');   // newest first
            sb.Append(Log);
            Log = sb.Length > 8000 ? sb.ToString(0, 8000) : sb.ToString();
        }

        while (_pendingDownloads.TryDequeue(out var d))
            foreach (var row in Files)
                if (row.Item.Id == d.Id) { row.AddDownload(d.Bytes, d.Complete); break; }

        DrainChat();
        DrainUploads();

        var s = _hub;
        if (s is null) return queued;
        long activity = s.BytesSent + s.BytesReceived + s.TotalConnections + s.ActiveConnections + s.ClientCount;
        bool moved = activity != _lastActivity;
        _lastActivity = activity;
        ActiveConnections = s.ActiveConnections;
        TotalConnections = s.TotalConnections;
        TotalDownloads = s.Downloads;
        BytesSentText = FileHttpServer.HumanSize(s.BytesSent);
        BytesReceivedText = FileHttpServer.HumanSize(s.BytesReceived);
        ClientCount = s.ClientCount;
        UpdateLiveStatus();
        return queued || moved;
    }

    private long _lastActivity = -1;
}
