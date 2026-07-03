using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;
using Renci.SshNet;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;

namespace Echoes.ViewModels;

public partial class SshViewModel : ObservableObject
{
    [ObservableProperty] private string _host = string.Empty;
    [ObservableProperty] private int _port = 22;
    [ObservableProperty] private string _username = "root";
    [ObservableProperty] private string _password = string.Empty;
    [ObservableProperty] private string _commandInput = string.Empty;
    [ObservableProperty] private string _terminalOutput = string.Empty;
    [ObservableProperty] private bool _isConnected;

    [ObservableProperty] private bool _connectViaProxy;
    [ObservableProperty] private string _proxyInHost = "127.0.0.1";
    [ObservableProperty] private int _proxyInPort = 1080;

    [ObservableProperty] private bool _enableSocksTunnel;
    [ObservableProperty] private int _tunnelPort = 8080;
    [ObservableProperty] private string _tunnelHost = "127.0.0.1";
    [ObservableProperty] private string _tunnelStatus = "Tunnel: Offline";

    public ObservableCollection<string> HostHistory => HistoryService.Instance.Get("ssh.host");
    public ObservableCollection<string> UserHistory => HistoryService.Instance.Get("ssh.user");

    private bool _loaded;
    // NOTE: Password is intentionally NOT persisted (sensitive).
    private static readonly HashSet<string> PersistProps = new()
    { "Host", "Port", "Username", "ConnectViaProxy", "ProxyInHost", "ProxyInPort",
      "EnableSocksTunnel", "TunnelHost", "TunnelPort" };

    public SshViewModel()
    {
        var ps = ProfileService.Instance;
        ps.Remove("ssh.pass");   // purge any password saved by an earlier build
        Host = ps.GetSetting("ssh.host") ?? (HistoryService.Instance.Last("ssh.host") ?? string.Empty);
        Port = ps.GetInt("ssh.port", 22);
        Username = ps.GetSetting("ssh.user") ?? (HistoryService.Instance.Last("ssh.user") ?? "root");
        ConnectViaProxy = ps.GetBool("ssh.inEnabled");
        ProxyInHost = ps.GetSetting("ssh.inHost") ?? "127.0.0.1";
        ProxyInPort = ps.GetInt("ssh.inPort", 1080);
        EnableSocksTunnel = ps.GetBool("ssh.outEnabled");
        TunnelHost = ps.GetSetting("ssh.outHost") ?? "127.0.0.1";
        TunnelPort = ps.GetInt("ssh.outPort", 8080);
        _loaded = true;
    }

    private CancellationTokenSource? _persistCts;

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loaded && e.PropertyName is { } n && PersistProps.Contains(n))
            SchedulePersist();
    }

    // Typing into Host/User/… raises PropertyChanged per keystroke; debounce so we don't
    // re-serialize + rewrite the whole profile file on the UI thread on every character.
    private void SchedulePersist()
    {
        _persistCts?.Cancel();
        var cts = _persistCts = new CancellationTokenSource();
        _ = Task.Delay(600, cts.Token).ContinueWith(t =>
        {
            if (t.IsCanceled) return;
            ProfileService.Instance.SetMany(
                ("ssh.host", Host), ("ssh.port", Port.ToString()), ("ssh.user", Username),
                ("ssh.inEnabled", ConnectViaProxy ? "true" : "false"), ("ssh.inHost", ProxyInHost), ("ssh.inPort", ProxyInPort.ToString()),
                ("ssh.outEnabled", EnableSocksTunnel ? "true" : "false"), ("ssh.outHost", TunnelHost), ("ssh.outPort", TunnelPort.ToString()));
        }, TaskScheduler.Default);
    }

    private readonly List<string> _history = new();
    private int _historyIndex = -1;
    private SshClient? _client;
    private ShellStream? _shellStream;
    private ForwardedPortDynamic? _dynamicForward;
    private CancellationTokenSource? _readerCts = new();


    [RelayCommand]
    private async Task ToggleConnect()
    {
        if (IsConnected) { StopSsh(); return; }
        if (string.IsNullOrWhiteSpace(Host) || string.IsNullOrWhiteSpace(Username)) return;

        HistoryService.Instance.Add("ssh.host", Host);
        HistoryService.Instance.Add("ssh.user", Username);

        string hostId = $"{Host}:{Port}";
        string? hostKeyError = null;

        await Task.Run(() =>
        {
            try
            {
                var authMethod = new PasswordAuthenticationMethod(Username, Password);
                ConnectionInfo connInfo = ConnectViaProxy
                    ? new ConnectionInfo(Host, Port, Username, ProxyTypes.Socks5, ProxyInHost, ProxyInPort, string.Empty, string.Empty, authMethod)
                    : new ConnectionInfo(Host, Port, Username, authMethod);

                _client = new SshClient(connInfo);

                // Host-key verification (trust-on-first-use, then pin). Rejects key changes (MITM).
                _client.HostKeyReceived += (s, e) =>
                {
                    string fp = Convert.ToHexString(SHA256.HashData(e.HostKey));
                    var stored = ProfileService.Instance.GetKnownHost(hostId);
                    if (stored != null)
                    {
                        if (stored == fp)
                        {
                            e.CanTrust = true;
                        }
                        else
                        {
                            e.CanTrust = false;
                            hostKeyError =
                                $"# ⚠ HOST KEY MISMATCH for {hostId}\n" +
                                $"#   expected: SHA256:{stored}\n" +
                                $"#   received: SHA256:{fp}\n" +
                                "#   Possible MITM — connection refused.\n" +
                                "#   If the host key legitimately changed, remove its pin from the Echoes profile and reconnect.\n";
                        }
                    }
                    else
                    {
                        e.CanTrust = true;          // trust on first use
                        ProfileService.Instance.SetKnownHost(hostId, fp);
                    }
                };

                _client.Connect();

                if (EnableSocksTunnel)
                {
                    _dynamicForward = new ForwardedPortDynamic(TunnelHost, (uint)TunnelPort);
                    _client.AddForwardedPort(_dynamicForward);
                    _dynamicForward.Start();
                    Avalonia.Threading.Dispatcher.UIThread.Post(() => TunnelStatus = $"SOCKS5 Proxy: {TunnelHost}:{TunnelPort}");
                }

                _shellStream = _client.CreateShellStream("vt100", 80, 24, 800, 600, 1024);

                Avalonia.Threading.Dispatcher.UIThread.Post(() => IsConnected = true);

                _readerCts = new CancellationTokenSource();
                _ = Task.Run(() => ReadFromStream(_readerCts.Token));
            }
            catch (Exception ex)
            {
                AppendToTerminal(hostKeyError ?? $"# Connection Error: {ex.Message}\n");
                StopSsh();
            }
        });
    }

    private async Task ReadFromStream(CancellationToken token)
    {
        var buffer = new byte[1024];
        while (!token.IsCancellationRequested && _shellStream != null && _client is { IsConnected: true })
        {
            try
            {
                if (_shellStream.DataAvailable)
                {
                    int bytesRead = _shellStream.Read(buffer, 0, buffer.Length);
                    if (bytesRead > 0)
                    {
                        string rawData = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        string cleanData = SanitizeAnsi(rawData);
                        AppendToTerminal(cleanData);
                    }
                }
                else
                {
                    await Task.Delay(5, token);
                }
            }
            catch { break; }
        }
    }

    private void AppendToTerminal(string text)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            TerminalOutput += text;
            if (TerminalOutput.Length > 40000)   // trim less often to avoid O(n) churn on every read
            {
                TerminalOutput = TerminalOutput[^30000..];
            }
        });
    }

    private string SanitizeAnsi(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        string pattern = @"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\x1B\]0;.*?\x07|\x1B\]0;.*?\x1B\\|\x07|\x1B\(B";
        string result = Regex.Replace(input, pattern, string.Empty);
        return result.Replace("\r\n", "\n").Replace("\r", "\n");
    }

    [RelayCommand]
    private void SendCommand()
    {
        if (_shellStream != null && _client is { IsConnected: true } && !string.IsNullOrEmpty(CommandInput))
        {
            _shellStream.Write(CommandInput + "\r");
            _shellStream.Flush();

            _history.Add(CommandInput);
            _historyIndex = _history.Count;
            CommandInput = string.Empty;
        }
    }

    [RelayCommand]
    private void HistoryUp()
    {
        if (_history.Count > 0 && _historyIndex > 0)
        {
            _historyIndex--;
            CommandInput = _history[_historyIndex];
        }
    }

    [RelayCommand]
    private void HistoryDown()
    {
        if (_historyIndex < _history.Count - 1)
        {
            _historyIndex++;
            CommandInput = _history[_historyIndex];
        }
        else
        {
            _historyIndex = _history.Count;
            CommandInput = string.Empty;
        }
    }

    private void StopSsh()
    {
        try
        {
            _readerCts?.Cancel();
            _dynamicForward?.Stop();
            _shellStream?.Dispose();
            _client?.Disconnect();
            _client?.Dispose();
        }
        catch { }
        // StopSsh may run on a background thread (connect-failure path); marshal bound state.
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            IsConnected = false;
            TunnelStatus = "Tunnel: Offline";
        });
        AppendToTerminal("\n# Disconnected.\n");
    }
}