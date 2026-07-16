using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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
    [ObservableProperty] private string _statusMessage = "Add files, then START.";
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

    private IReadOnlyList<SharedItem> SnapshotItems()
    {
        lock (_itemsLock) return _items.ToArray();
    }

    // Prepare the app icon for the web index page once (downscaled to a light data: URI).
    static WebServerViewModel() => FileHttpServer.BrandLogoDataUri = TryBuildLogoDataUri();

    // Load Assets/logo.png, shrink it to ~128px (the full asset is multi-MB), PNG-encode → data: URI.
    private static string? TryBuildLogoDataUri()
    {
        try
        {
            using var s = Avalonia.Platform.AssetLoader.Open(new Uri("avares://Echoes/Assets/logo.png"));
            using var src = new Bitmap(s);
            var ps = src.PixelSize;
            const int max = 128;
            int w, h;
            if (ps.Width >= ps.Height) { w = max; h = Math.Max(1, (int)Math.Round(max * (double)ps.Height / ps.Width)); }
            else { h = max; w = Math.Max(1, (int)Math.Round(max * (double)ps.Width / ps.Height)); }
            using var scaled = src.CreateScaledBitmap(new Avalonia.PixelSize(w, h), BitmapInterpolationMode.HighQuality);
            using var ms = new MemoryStream();
            scaled.Save(ms);
            return "data:image/png;base64," + Convert.ToBase64String(ms.ToArray());
        }
        catch { return null; }
    }

    public WebServerViewModel()
    {
        RebuildBindOptions();
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
            new("All interfaces (0.0.0.0) — visible on your LAN", IPAddress.Any, "all"),
            new("Localhost only (127.0.0.1) — this device", IPAddress.Loopback, "loopback"),
        };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        list.Add(new BindOption($"{ua.Address}  ({ni.Name})", ua.Address, "iface"));
            }
        }
        catch { /* GetIPProperties can throw on restricted platforms — keep All + Localhost */ }

        _rebuildingBinds = true;
        BindOptions.Clear();
        foreach (var o in list) BindOptions.Add(o);
        SelectedBind = BindOptions.FirstOrDefault(o => o.Kind == prevKind && o.Address.ToString() == prevAddr)
                       ?? BindOptions.FirstOrDefault(o => o.Kind == "all")
                       ?? BindOptions.FirstOrDefault();
        _rebuildingBinds = false;
    }

    partial void OnSelectedBindChanged(BindOption? value)
    {
        if (!_rebuildingBinds) RefreshAddresses();
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
    public void AddSharedFile(string name, long size, Func<Task<Stream>> open)
    {
        var item = new SharedItem
        {
            Id = Guid.NewGuid().ToString("N")[..10],
            Name = name,
            Size = size,
            ContentType = FileHttpServer.GuessContentType(name),
            Open = open,
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

        IPAddress bind = SelectedBind?.Address ?? IPAddress.Any;
        try
        {
            ResetStats();
            _server = new FileHttpServer(SnapshotItems, RequireAuth ? AuthUser : null, RequireAuth ? AuthPass : null,
                AppendLog, OnStats, OnDownload, MaxConnections);
            _server.Start(bind, Port);
            IsRunning = true;
            BackgroundGuard.Acquire("Sharing files");
            RefreshAddresses();
            StatusMessage = $"Live on :{Port} — open a URL below.";
            AppendLog($"server started on {bind}:{Port} (max {MaxConnections} connections)");
        }
        catch (SocketException ex)
        {
            _server = null;
            StatusMessage = ex.SocketErrorCode is SocketError.AddressAlreadyInUse
                ? $"Port {Port} is already in use — pick another port."
                : "Cannot start server: " + ex.Message;
        }
        catch (Exception ex)
        {
            _server = null;
            StatusMessage = "Cannot start server: " + ex.Message;
        }
    }

    private void StopInternal()
    {
        bool wasRunning = IsRunning;
        try { _server?.Dispose(); } catch { }
        _server = null;
        IsRunning = false;
        if (wasRunning)
        {
            BackgroundGuard.Release();
            AppendLog("server stopped");
            StatusMessage = "Stopped.";
        }
    }

    /// <summary>Stop the server on app shutdown (releases the listening socket + background guard).</summary>
    public void StopServer() => StopInternal();

    [RelayCommand]
    private void RefreshAddresses()
    {
        RebuildBindOptions();     // interfaces/IPs may have changed since last time
        Addresses.Clear();

        string kind = SelectedBind?.Kind ?? "all";
        if (kind == "loopback")
        {
            Addresses.Add($"http://127.0.0.1:{Port}/");
        }
        else if (kind == "iface" && SelectedBind is not null)
        {
            Addresses.Add($"http://{SelectedBind.Address}:{Port}/");
        }
        else // all interfaces → list every reachable LAN IPv4 so any of them works
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                        if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                            Addresses.Add($"http://{ua.Address}:{Port}/");
                }
            }
            catch { }
            if (Addresses.Count == 0) Addresses.Add($"http://localhost:{Port}/");
        }

        // keep the current QR target if it survived the refresh, else point at the first address
        if (SelectedShareUrl is null || !Addresses.Contains(SelectedShareUrl))
            SelectedShareUrl = Addresses.FirstOrDefault();
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

    // Stats callbacks fire on connection threads → marshal to the UI thread before touching bound state.
    private void OnStats()
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            var s = _server;
            if (s is null) return;
            ActiveConnections = s.ActiveConnections;
            TotalConnections = s.TotalConnections;
            TotalDownloads = s.TotalDownloads;
            BytesSentText = FileHttpServer.HumanSize(s.BytesSent);
            ClientCount = s.ClientCount;
        });
    }

    private void OnDownload(string id, long bytes)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            foreach (var row in Files)
                if (row.Item.Id == id) { row.AddDownload(bytes); break; }
        });
    }

    // Server callback — fires on connection threads, so marshal to the UI thread.
    private void AppendLog(string line)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            string entry = $"[{DateTime.Now:HH:mm:ss}] {line}\n";
            Log = entry + Log;
            if (Log.Length > 8000) Log = Log[..8000];
        });
    }
}
