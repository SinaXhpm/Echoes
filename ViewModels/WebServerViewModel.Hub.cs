using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// "Share &amp; chat": starting / stopping the <see cref="ShareHub"/>, HTTPS (automatic, with a plain-HTTP fallback
/// that says why) and the PIN. The hub calls back on its connection threads; those calls only queue, and the 250 ms UI
/// timer drains the queues (chat, uploads, downloads, log) in one batch.
/// </summary>
public partial class WebServerViewModel : IShareHubSink
{
    /// <summary>HTTPS with this device's own certificate (default). Off = plain HTTP.</summary>
    [ObservableProperty] private bool _httpsOn = true;
    /// <summary>An 8-digit PIN guards the page (default). Off = anyone who can reach the port joins.</summary>
    [ObservableProperty] private bool _pinOn = true;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(PinText))] private string _pin = string.Empty;
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsIdle))] private bool _isStarting;
    [ObservableProperty] private bool _isHttpsActive;
    /// <summary>"SHA-256 4F:2A:9C:3D:11:E0:7B:42…" while running over HTTPS.</summary>
    [ObservableProperty] private string _certText = string.Empty;
    [ObservableProperty] private string _certTip = string.Empty;
    /// <summary>HTTPS was asked for but couldn't be used here: why (the hub then runs on plain HTTP).</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasTlsNote))] private string? _tlsNote;
    /// <summary>The selected address + "#k=PIN": what the QR shows and Copy / Open use.</summary>
    [ObservableProperty] private string _shareLink = string.Empty;
    [ObservableProperty] private bool _showRunningPin;

    public string PinText => Pin.Length == PinDigits ? Pin[..4] + " " + Pin[4..] : Pin;
    public bool HasTlsNote => !string.IsNullOrEmpty(TlsNote);
    /// <summary>Settings can be edited (they're captured when the hub starts).</summary>
    public bool IsIdle => !IsRunning && !IsStarting;

    private ShareHub? _hub;
    private ShareCert? _cert;
    private bool _runningPinOn;
    private int _startGen;
    // The chat outlives a stop: the next start continues it (pages that reconnect load it again).
    private IReadOnlyList<ShareMessage> _history = Array.Empty<ShareMessage>();

    // Hub → UI queues (connection threads enqueue; FlushUi drains). A null message = "chat cleared".
    private readonly ConcurrentQueue<ShareMessage?> _pendingChat = new();
    private readonly ConcurrentQueue<(ShareUpload Upload, string? Path, string? Error, bool Started)> _pendingUploads = new();

    partial void OnIsRunningChanged(bool value)
    {
        OnPropertyChanged(nameof(IsIdle));
        OnPropertyChanged(nameof(CanSendChat));
        OnPropertyChanged(nameof(CanAttach));
    }

    partial void OnHttpsOnChanged(bool value)
    {
        if (!_restoringShare) ProfileService.Instance.SetBool(KPlainHttp, !value);
    }

    partial void OnPinOnChanged(bool value)
    {
        if (!_restoringShare) ProfileService.Instance.SetBool(KNoPin, !value);
    }

    // ================================================================ PIN

    // 8 digits: with the hub's global miss limit a stranger needs months for the whole space (6 digits: days). The page (4-9
    // digits), the link and Basic auth take it as is; a stored 6-digit PIN from an earlier version is replaced at launch.
    private const int PinDigits = 8;
    private static string NewPinValue() => RandomNumberGenerator.GetInt32(0, 100_000_000).ToString("D8", CultureInfo.InvariantCulture);

    private void RestorePin(ProfileService p)
    {
        string stored = SecretProtector.Unprotect(p.GetSetting(KPin));
        if (stored.Length == PinDigits && stored.All(char.IsAsciiDigit))
        {
            Pin = stored;
            return;
        }
        Pin = NewPinValue();
        SavePin();
    }

    // Sealed. With no usable key file this run a stored PIN may only be unreadable for now: not written over.
    private void SavePin()
    {
        if (!SecretProtector.IsKeyAvailable && ProfileService.Instance.GetSetting(KPin) is { Length: > 0 }) return;
        ProfileService.Instance.SetSetting(KPin, SecretProtector.Protect(Pin));
    }

    /// <summary>A new random PIN. While sharing, every browser is logged out and needs the new one.</summary>
    [RelayCommand]
    private void NewPin()
    {
        Pin = NewPinValue();
        SavePin();
        if (_hub is { } hub && _runningPinOn)
        {
            hub.SetPin(Pin);
            AppendLog("new PIN: every browser has to enter it again");
        }
        UpdateShareLink();
        FlushUi();
    }

    [RelayCommand]
    private async Task CopyPin()
    {
        if (Pin.Length > 0) await ClipboardHelper.SetTextAsync(Pin);
    }

    // ================================================================ link + QR

    /// <summary>The link for an address: with the PIN in the fragment (never sent to the server, read by the page and
    /// removed from the address bar) when the running hub needs one.</summary>
    private string LinkFor(string url) => IsRunning && _runningPinOn && Pin.Length > 0 ? url + "#k=" + Pin : url;

    private void UpdateShareLink()
    {
        string link = SelectedShareUrl is { Length: > 0 } u ? LinkFor(u) : string.Empty;
        ShareLink = link;
        var old = QrImage;
        // only while running (the link row shows then) — no QR per keystroke in the port box
        QrImage = IsRunning && link.Length > 0 ? BuildQr(link) : null;
        old?.Dispose();
    }

    [RelayCommand]
    private async Task CopyLink()
    {
        if (ShareLink.Length > 0) await ClipboardHelper.SetTextAsync(ShareLink);
    }

    [RelayCommand]
    private void OpenLink() => LinkHelper.Open(ShareLink.Length > 0 ? ShareLink : null);

    // ================================================================ start / stop

    private async Task StartAsync()
    {
        StatusIsError = false;
        if (Port is < 1 or > 65535) { Fail("Port must be between 1 and 65535."); return; }
        var bind = SelectedBind ?? BindOptions.FirstOrDefault() ?? new BindOption("All", IPAddress.IPv6Any, "all");
        bool https = HttpsOn, pinOn = PinOn;
        int port = Port;
        if (pinOn && Pin.Length != PinDigits) { Pin = NewPinValue(); SavePin(); }
        int gen = ++_startGen;
        IsStarting = true;
        TlsNote = null;
        StatusMessage = https ? "Preparing HTTPS…" : "Starting…";
        FlushUi();      // show any stragglers from the previous run before resetting
        ResetStats();

        string inbox = HubInboxFolder();
        string parts = OperatingSystem.IsAndroid() ? ShareInbox.AppInboxFolder() : string.Empty;
        ShareCert? cert = null;
        string? tlsNote = null;
        ShareHub? hub = null;
        string? error = null;
        try
        {
            if (https) (cert, tlsNote) = await Task.Run(PrepareTlsAsync);
            hub = new ShareHub(new ShareHubOptions
            {
                Bind = bind.Address,
                Port = port,
                Cert = cert,
                RequirePin = pinOn,
                Pin = Pin,
                MaxConnections = MaxConnections,
                InboxFolder = inbox,
                PartFolder = parts,
                MaxUploadBytes = MaxUploadBytes,
                HostName = HostDisplayName(),
                Items = SnapshotItems,
                History = _history,
            }, this);
            var h = hub;
            await Task.Run(() =>
            {
                ShareHub.DeleteStaleParts(parts.Length > 0 ? parts : inbox);
                h.Start();
            });
        }
        catch (Exception ex)
        {
            string where = bind.Kind switch { "all" => $"port {port}", "loopback" => $"127.0.0.1:{port}", _ => $"{bind.Address}:{port}" };
            error = "Couldn't start: " + SocketErrors.Describe(ex, SocketAction.Listen, where, port);
        }

        if (gen != _startGen || error is not null)
        {
            // stopped while starting, or it failed: nothing of this attempt stays
            try { hub?.Stop(); } catch { }
            cert?.Dispose();
            if (gen == _startGen)
            {
                IsStarting = false;
                Fail(error ?? "Couldn't start.");
            }
            return;
        }

        _hub = hub;
        _cert = cert;
        _activeBind = bind.Address;
        _activePort = port;
        _runningPinOn = pinOn;
        IsHttpsActive = cert is not null;
        TlsNote = tlsNote is null ? null : $"HTTPS isn't available here ({tlsNote}), so this runs on plain HTTP.";
        CertText = cert is null ? string.Empty : "SHA-256 " + cert.ShortFingerprint + "…";
        CertTip = cert is null ? string.Empty
            : "This device's own certificate, SHA-256:\n" + cert.Fingerprint
              + "\n\nBrowsers warn once because nobody vouches for it. Compare the start with what the browser's "
              + "certificate details show, then accept it.";
        ShowRunningPin = pinOn;
        IsStarting = false;
        IsRunning = true;
        StatusIsError = false;
        BackgroundGuard.Acquire("Sharing & chat");
        RefreshAddresses();
        UpdateShareLink();
        AppendLog($"sharing on {(bind.Kind == "all" ? "all interfaces" : bind.Address.ToString())}:{port} — "
                  + (cert is not null ? "HTTPS" : "HTTP") + (pinOn ? ", PIN" : ", no PIN"));
        if (cert?.Regenerated == true) AppendLog("new certificate: browsers warn once for it (SHA-256 " + cert.ShortFingerprint + "…)");
        if (tlsNote is not null) AppendLog("HTTPS unavailable: " + tlsNote);
        if (_uiTimer is null)
        {
            _uiTimer = new Avalonia.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
            _uiTimer.Tick += (_, _) => FlushUi();
        }
        _uiTimer.Start();
        FlushUi();
    }

    // Off the UI thread: the stored certificate (or a new one), then a loopback handshake proving this platform can
    // serve it. Any failure: plain HTTP, with the reason.
    private static async Task<(ShareCert? Cert, string? Note)> PrepareTlsAsync()
    {
        ShareCert? cert = null;
        try
        {
            cert = ShareTls.LoadOrCreate();
            string? why = await ShareTls.SelfTestAsync(cert, CancellationToken.None).ConfigureAwait(false);
            if (why is null) return (cert, null);
            cert.Dispose();
            return (null, why);
        }
        catch (Exception ex)
        {
            cert?.Dispose();
            var e = SocketErrors.Unwrap(ex);
            return (null, e is PlatformNotSupportedException or NotSupportedException or NotImplementedException
                ? "this system can't make or serve a certificate"
                : WsProtocol.Short(e.Message.Trim(), 160));
        }
    }

    private void Fail(string message)
    {
        StatusMessage = message;
        StatusIsError = true;
    }

    private void StopInternal()
    {
        _startGen++;                       // a start still preparing is abandoned
        bool wasRunning = IsRunning;
        var hub = _hub;
        _hub = null;
        if (hub is not null)
        {
            _history = hub.Messages();
            try { hub.Stop(); } catch { }
        }
        var cert = _cert;
        _cert = null;
        // the certificate's key may still be in use by connections closing down: let them go first
        if (cert is not null) _ = Task.Delay(3000).ContinueWith(_ => cert.Dispose(), TaskScheduler.Default);
        _uiTimer?.Stop();
        FlushUi();          // last poll of the stopped hub's queues
        _activeBind = null;
        IsStarting = false;
        IsRunning = false;
        IsHttpsActive = false;
        ShowRunningPin = false;
        UpdateShareLink();
        RefreshStored();    // partial uploads the hub dropped on stop no longer count
        if (wasRunning)
        {
            BackgroundGuard.Release();
            AppendLog("stopped");
            StatusMessage = "Stopped.";
            StatusIsError = false;
            FlushUi();
        }
    }

    /// <summary>This device in the chat: its host name (on Android the phone's own name, else "Echoes").</summary>
    private static string HostDisplayName()
    {
        string n = AppInfo.DeviceName ?? string.Empty;
        if (string.IsNullOrWhiteSpace(n))
            try { n = Environment.MachineName; } catch { }
        if (string.IsNullOrWhiteSpace(n) || n.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return "Echoes";
        return ShareHub.CleanName(n);
    }

    private void UpdateLiveStatus()
    {
        if (!IsRunning) return;
        int n = ClientCount;
        string text = n switch
        {
            0 => "Open the link or scan the QR on the other device.",
            1 => "1 device connected.",
            _ => $"{n} devices connected.",
        };
        if (!_runningPinOn && _activeBind is { } b && !IPAddress.IsLoopback(b)) text += "  ⚠ No PIN: anyone on your network can join.";
        if (StatusMessage != text) StatusMessage = text;
    }

    // ================================================================ hub callbacks (connection threads: queue only)

    void IShareHubSink.OnLog(string line) => AppendLog(line);
    void IShareHubSink.OnMessage(ShareMessage message) => _pendingChat.Enqueue(message);
    void IShareHubSink.OnChatCleared() => _pendingChat.Enqueue(null);
    void IShareHubSink.OnUploadStarted(ShareUpload upload) => _pendingUploads.Enqueue((upload, null, null, true));
    void IShareHubSink.OnUploadFinished(ShareUpload upload, string? path, string? error) => _pendingUploads.Enqueue((upload, path, error, false));
    void IShareHubSink.OnDownload(string itemId, long bytes, bool complete) => _pendingDownloads.Enqueue((itemId, bytes, complete));
}
