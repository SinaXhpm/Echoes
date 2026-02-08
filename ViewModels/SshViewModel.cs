using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Renci.SshNet;
using System;
using System.Collections.Generic;
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

        await Task.Run(() =>
        {
            try
            {
                var authMethod = new PasswordAuthenticationMethod(Username, Password);
                ConnectionInfo connInfo = ConnectViaProxy
                    ? new ConnectionInfo(Host, Port, Username, ProxyTypes.Socks5, ProxyInHost, ProxyInPort, string.Empty, string.Empty, authMethod)
                    : new ConnectionInfo(Host, Port, Username, authMethod);

                _client = new SshClient(connInfo);
                _client.Connect();

                if (EnableSocksTunnel)
                {
                    _dynamicForward = new ForwardedPortDynamic(TunnelHost, (uint)TunnelPort);
                    _client.AddForwardedPort(_dynamicForward);
                    _dynamicForward.Start();
                    TunnelStatus = $"SOCKS5 Proxy: {TunnelHost}:{TunnelPort}";
                }

                _shellStream = _client.CreateShellStream("vt100", 80, 24, 800, 600, 1024);

                IsConnected = true;

                _readerCts = new CancellationTokenSource();
                _ = Task.Run(() => ReadFromStream(_readerCts.Token));
            }
            catch (Exception ex)
            {
                AppendToTerminal($"# Connection Error: {ex.Message}\n");
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
            if (TerminalOutput.Length > 30000)
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
        IsConnected = false;
        TunnelStatus = "Tunnel: Offline";
        AppendToTerminal("\n# Disconnected.\n");
    }
}