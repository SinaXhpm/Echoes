using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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

    public void AddDownload(long bytes)
    {
        Downloads++;
        BytesServed += bytes;
        OnPropertyChanged(nameof(HasDownloads));
    }

    public void ResetStats()
    {
        Downloads = 0;
        BytesServed = 0;
        OnPropertyChanged(nameof(HasDownloads));
    }
}

/// <summary>One entry in the "how to listen" dropdown. <see cref="Kind"/> is "all" | "loopback" | "iface".</summary>
public sealed record BindOption(string Label, IPAddress Address, string Kind);

/// <summary>
/// A cross-platform LAN file-share server. Pick files, press START, and anyone on the same network
/// downloads them from the shown URL(s). Runs on a managed <see cref="FileHttpServer"/> (TcpListener),
/// so it works on desktop and the Android sandbox with no external binary, driver, or admin/root.
/// </summary>
public partial class WebServerViewModel : ObservableObject
{
    [ObservableProperty] private int _port = 8080;
    [ObservableProperty] private int _maxConnections = 24;         // concurrent-connection cap
    [ObservableProperty] private bool _requireAuth = false;
    [ObservableProperty] private string _authUser = "echoes";
    [ObservableProperty] private string _authPass = string.Empty;
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "Add files, then start sharing.";
    [ObservableProperty] private string _log = string.Empty;

    // How the server binds: all interfaces (LAN-visible, default), loopback only, or one specific IP.
    public ObservableCollection<BindOption> BindOptions { get; } = new();
    [ObservableProperty] private BindOption? _selectedBind;
    private bool _rebuildingBinds;

    // QR of the selected share URL — scan it on a phone's camera to open the download page.
    [ObservableProperty] private string? _selectedShareUrl;
    [ObservableProperty] private Bitmap? _qrImage;

    // Live stats (downloads + network connections).
    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private long _totalConnections;
    [ObservableProperty] private long _totalDownloads;
    [ObservableProperty] private string _bytesSentText = "0 B";
    [ObservableProperty] private int _clientCount;

    public ObservableCollection<SharedFileRow> Files { get; } = new();
    public ObservableCollection<string> Addresses { get; } = new();

    public bool HasFiles => Files.Count > 0;

    // Thread-safe source of truth the server reads from connection threads.
    private readonly object _itemsLock = new();
    private readonly List<SharedItem> _items = new();
    private FileHttpServer? _server;

    // The endpoint the live listener ACTUALLY bound (captured at START). While running, the shown
    // URLs/QR come from these, never from the editable settings.
    private IPAddress? _activeBind;
    private int _activePort;

    // Server callbacks fire on connection threads — possibly thousands per second under a LAN flood.
    // They only enqueue; a 250 ms UI timer (running while live) drains the queues and polls the
    // counters, so the UI cost is flat whatever the load (one UI post per event could swamp it).
    private readonly ConcurrentQueue<string> _pendingLog = new();
    private readonly ConcurrentQueue<(string Id, long Bytes)> _pendingDownloads = new();
    private Avalonia.Threading.DispatcherTimer? _uiTimer;
    private const int MaxPendingLog = 200;   // the TextBox keeps only ~8000 chars anyway

    private IReadOnlyList<SharedItem> SnapshotItems()
    {
        lock (_itemsLock) return _items.ToArray();
    }

    // Decode Assets/logo-256.png (a 256px copy of the multi-MB logo.png), shrink it to ~128px, PNG-encode → data: URI.
    private static string? TryBuildLogoDataUri(Stream s)
    {
        try
        {
            using var src = new Bitmap(s);
            var ps = src.PixelSize;
            const int max = 128;
            int w, h;
            if (ps.Width >= ps.Height) { w = max; h = Math.Max(1, (int)Math.Round(max * (double)ps.Height / ps.Width)); }
            else { h = max; w = Math.Max(1, (int)Math.Round(max * (double)ps.Width / ps.Height)); }
            using var scaled = src.CreateScaledBitmap(new Avalonia.PixelSize(w, h), BitmapInterpolationMode.HighQuality);
            using var ms = new MemoryStream();
            scaled.Save(ms, PngBitmapEncoderOptions.Default);   // explicit PNG — the data: URI below says image/png
            return "data:image/png;base64," + Convert.ToBase64String(ms.ToArray());
        }
        catch { return null; }
    }

    public WebServerViewModel()
    {
        RebuildBindOptions();
        RestoreShareSettings();
        InitCatcher();   // the "Catch requests" mode (WebServerViewModel.Catcher.cs)
        // Prepare the app icon for the web index page once (downscaled to a light data: URI) — decoded in
        // the background: doing it here stalled the UI thread, and a null URI is handled (the index falls
        // back to a vector mark until it's ready). Only the asset OPEN stays on this thread (a cheap slice
        // of the embedded resource), so Avalonia's asset loader is never used from two threads at once.
        if (FileHttpServer.BrandLogoDataUri is null)
        {
            Stream? logo = null;
            try { logo = Avalonia.Platform.AssetLoader.Open(new Uri("avares://Echoes/Assets/logo-256.png")); } catch { }
            if (logo is { } s)
                _ = Task.Run(() =>
                {
                    using (s) FileHttpServer.BrandLogoDataUri ??= TryBuildLogoDataUri(s);
                });
        }
    }

    // --- bind-interface selection ---

    // Rebuild the "how to listen" dropdown: All interfaces + Localhost + one row per live IPv4.
    // Preserves the current pick if it still exists, else defaults to All (0.0.0.0).
    private void RebuildBindOptions()
    {
        string? prevKind = SelectedBind?.Kind;
        string? prevAddr = SelectedBind?.Address.ToString();

        var list = new List<BindOption>
        {
            new("All interfaces (0.0.0.0)", IPAddress.Any, "all"),
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

    partial void OnSelectedBindChanged(BindOption? value)
    {
        if (_rebuildingBinds) return;
        if (!_restoringShare && value is not null)
            ProfileService.Instance.SetSetting(KShareBind, value.Kind == "iface" ? value.Address.ToString() : value.Kind);
        RefreshAddresses();
    }

    // --- remembered share settings: each saved when it changes. The password only sealed (SecretProtector "enc2:"); one
    // that doesn't open on this run stays on disk as stored until a new one is typed. The shared files are not kept:
    // picks from a phone's file picker only last for the session, and a stale path list would share the wrong files.

    private const string KSharePort = "webserver.port", KShareMaxConn = "webserver.maxConn", KShareAuth = "webserver.auth",
        KShareUser = "webserver.user", KSharePass = "webserver.pass", KShareBind = "webserver.bind";
    private bool _restoringShare;

    private void RestoreShareSettings()
    {
        var p = ProfileService.Instance;
        _restoringShare = true;
        try
        {
            int port = p.GetInt(KSharePort, 8080);
            Port = port is >= 1 and <= 65535 ? port : 8080;
            MaxConnections = Math.Clamp(p.GetInt(KShareMaxConn, 24), 1, 512);
            RequireAuth = p.GetBool(KShareAuth);
            AuthUser = p.GetSetting(KShareUser) ?? "echoes";
            AuthPass = SecretProtector.Unprotect(p.GetSetting(KSharePass));
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
    }

    partial void OnPortChanged(int value)
    {
        if (!_restoringShare && value is >= 1 and <= 65535)
            ProfileService.Instance.SetSetting(KSharePort, value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    partial void OnMaxConnectionsChanged(int value)
    {
        if (!_restoringShare && value is >= 1 and <= 512)
            ProfileService.Instance.SetSetting(KShareMaxConn, value.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    partial void OnRequireAuthChanged(bool value) { if (!_restoringShare) ProfileService.Instance.SetBool(KShareAuth, value); }
    partial void OnAuthUserChanged(string value) { if (!_restoringShare) ProfileService.Instance.SetSetting(KShareUser, value ?? string.Empty); }

    partial void OnAuthPassChanged(string value)
    {
        if (!_restoringShare) ProfileService.Instance.SetSetting(KSharePass, string.IsNullOrEmpty(value) ? null : SecretProtector.Protect(value));
    }

    // --- QR of the selected share URL ---

    partial void OnSelectedShareUrlChanged(string? value)
    {
        var old = QrImage;
        QrImage = string.IsNullOrEmpty(value) ? null : BuildQr(value!);
        old?.Dispose();
    }

    // Renders a share URL to a crisp black/white QR bitmap (pure managed — see Helpers/QrCode.cs).
    private static Bitmap? BuildQr(string text)
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

    // Called from the view code-behind after the file picker resolves each file.
    public void AddSharedFile(string name, long size, Func<Task<Stream>> open, DateTime? lastModifiedUtc = null)
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
        Files.Add(new SharedFileRow { Item = item });
        OnPropertyChanged(nameof(HasFiles));
        StatusMessage = $"{Files.Count} file(s) ready to share.";
    }

    [RelayCommand]
    private void RemoveFile(SharedFileRow? row)
    {
        if (row is null) return;
        lock (_itemsLock) _items.Remove(row.Item);
        Files.Remove(row);
        OnPropertyChanged(nameof(HasFiles));
        StatusMessage = Files.Count == 0 ? "No files shared." : $"{Files.Count} file(s) ready to share.";
    }

    [RelayCommand]
    private void ClearFiles()
    {
        lock (_itemsLock) _items.Clear();
        Files.Clear();
        OnPropertyChanged(nameof(HasFiles));
        StatusMessage = "No files shared.";
    }

    [RelayCommand]
    private void ToggleServer()
    {
        if (IsRunning) StopInternal();
        else Start();
    }

    private void Start()
    {
        if (Port is < 1 or > 65535) { StatusMessage = "Port must be between 1 and 65535."; return; }
        if (Files.Count == 0) { StatusMessage = "Add at least one file to share."; return; }
        if (RequireAuth && string.IsNullOrEmpty(AuthUser)) { StatusMessage = "Enter a username for auth (or turn auth off)."; return; }
        // An empty password with the public default user "echoes" would look protected (the browser
        // still prompts) while anyone could log in with a blank password.
        if (RequireAuth && string.IsNullOrEmpty(AuthPass)) { StatusMessage = "Enter a password (or turn auth off)."; return; }

        IPAddress bind = SelectedBind?.Address ?? IPAddress.Any;
        try
        {
            FlushUi();      // show any stragglers from the previous run before resetting
            ResetStats();
            _server = new FileHttpServer(SnapshotItems, RequireAuth ? AuthUser : null, RequireAuth ? AuthPass : null,
                AppendLog, onStats: null, onDownload: OnDownload, maxConnections: MaxConnections);
            _server.Start(bind, Port);
            _activeBind = bind;
            _activePort = Port;
            IsRunning = true;
            BackgroundGuard.Acquire("Sharing files");
            RefreshAddresses();
            // No password on a LAN-reachable bind = anyone on the network can download the shared files. That's the
            // feature, so it isn't blocked — but say so plainly (as the proxy does) instead of a bare "live".
            bool openToLan = !RequireAuth && !IPAddress.IsLoopback(bind);
            StatusMessage = $"Live on :{Port} — open a URL below."
                            + (openToLan ? "  ⚠ No password: anyone on your network can download these files." : "");
            AppendLog($"server started on {bind}:{Port} (max {MaxConnections} connections)");
            if (_uiTimer is null)
            {
                _uiTimer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
                _uiTimer.Tick += (_, _) => FlushUi();
            }
            _uiTimer.Start();
        }
        catch (SocketException ex)
        {
            try { _server?.Dispose(); } catch { }   // frees the half-started listener socket + CTS
            _server = null;
            StatusMessage = ex.SocketErrorCode is SocketError.AddressAlreadyInUse
                ? $"Port {Port} is already in use — pick another port."
                : "Cannot start server: " + ex.Message;
        }
        catch (Exception ex)
        {
            if (IsRunning) StopInternal();   // failed after going live: undo guard/timer/flags too
            else { try { _server?.Dispose(); } catch { } _server = null; }
            StatusMessage = "Cannot start server: " + ex.Message;
        }
    }

    private void StopInternal()
    {
        bool wasRunning = IsRunning;
        try { _server?.Dispose(); } catch { }
        _uiTimer?.Stop();
        FlushUi();          // last poll of the stopped server's counters + queued lines
        _server = null;
        _activeBind = null;
        IsRunning = false;
        if (wasRunning)
        {
            BackgroundGuard.Release();
            AppendLog("server stopped");
            StatusMessage = "Stopped.";
            FlushUi();
        }
    }

    /// <summary>Stop both servers (file share + request catcher) on app shutdown (releases the sockets + background guard).</summary>
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
        if (live is null) RebuildBindOptions();     // interfaces/IPs may have changed since last time
        // Read the QR target before clearing: the share-link ListBox binds it two-way and writes null back when
        // Clear() resets the list, so the check below always fell back to the first URL on every refresh.
        string? picked = SelectedShareUrl;
        Addresses.Clear();

        int port = live is null ? Port : _activePort;
        string kind = live is null ? SelectedBind?.Kind ?? "all"
            : live.Equals(IPAddress.Any) ? "all"
            : live.Equals(IPAddress.Loopback) ? "loopback" : "iface";
        IPAddress? ifaceAddr = live ?? SelectedBind?.Address;
        if (kind == "loopback")
        {
            Addresses.Add($"http://127.0.0.1:{port}/");
        }
        else if (kind == "iface" && ifaceAddr is not null)
        {
            Addresses.Add($"http://{ifaceAddr}:{port}/");
        }
        else // all interfaces → list every reachable LAN IPv4 so any of them works
        {
            foreach (var (_, address) in NicSnapshot.UpIPv4())
                Addresses.Add($"http://{address}:{port}/");
            if (Addresses.Count == 0) Addresses.Add($"http://localhost:{port}/");
        }

        // keep the current QR target if it survived the refresh, else point at the first address
        SelectedShareUrl = picked is not null && Addresses.Contains(picked) ? picked : Addresses.FirstOrDefault();
    }

    [RelayCommand]
    private async Task CopyAddress(string? url)
    {
        if (!string.IsNullOrEmpty(url)) await ClipboardHelper.SetTextAsync(url);
    }

    [RelayCommand]
    private void OpenAddress(string? url) => LinkHelper.Open(url);

    private void ResetStats()
    {
        ActiveConnections = 0;
        TotalConnections = 0;
        TotalDownloads = 0;
        ClientCount = 0;
        BytesSentText = "0 B";
        foreach (var r in Files) r.ResetStats();
    }

    // Server callbacks — fire on connection threads, so they only enqueue (see _pendingLog).
    private void OnDownload(string id, long bytes) => _pendingDownloads.Enqueue((id, bytes));

    private void AppendLog(string line)
    {
        _pendingLog.Enqueue($"[{DateTime.Now:HH:mm:ss}] {line}");
        while (_pendingLog.Count > MaxPendingLog && _pendingLog.TryDequeue(out _)) { }   // flood: keep the newest
    }

    // UI thread: drain queued log lines / downloads into bound state and poll the live counters.
    private void FlushUi()
    {
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
                if (row.Item.Id == d.Id) { row.AddDownload(d.Bytes); break; }

        var s = _server;
        if (s is null) return;
        ActiveConnections = s.ActiveConnections;
        TotalConnections = s.TotalConnections;
        TotalDownloads = s.TotalDownloads;
        BytesSentText = FileHttpServer.HumanSize(s.BytesSent);
        ClientCount = s.ClientCount;
    }
}
