using Renci.SshNet;
using Renci.SshNet.Common;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Echoes.Helpers;

/// <summary>A connect failure whose message is already the one clear sentence to show.</summary>
public sealed class SshLoginException(string message) : Exception(message);

/// <summary>
/// One server's login, captured when Connect is pressed: what the session (and the SFTP connection opened later, which
/// is a second SSH connection) authenticates with. Edits to the form after that don't change a live session.
/// Login order is automatic: the key (if one is set) → the password → keyboard-interactive answered with the password.
/// </summary>
public sealed class SshLogin : IDisposable
{
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required string User { get; init; }
    public string Password { get; init; } = string.Empty;
    public string KeyPath { get; init; } = string.Empty;
    public string Passphrase { get; init; } = string.Empty;
    /// <summary>Opens a key picked through the platform's file picker (Android content URIs have no file path).</summary>
    public Func<Stream>? KeyOpener { get; init; }
    public bool UseProxy { get; init; }
    public string ProxyHost { get; init; } = string.Empty;
    public int ProxyPort { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);

    public bool HasKey => KeyPath.Length > 0;
    public bool HasPassword => Password.Length > 0;
    public PrivateKeyFile? Key { get; private set; }
    public string KeyKind { get; private set; } = string.Empty;
    /// <summary>Why the key couldn't be used (wrong passphrase, unsupported format…); null when it loaded or none is set.</summary>
    public string? KeyProblem { get; private set; }

    public string Endpoint => SshText.Endpoint(Host, Port);

    /// <summary>Reads and parses the key once (off the UI thread).</summary>
    public void LoadKey()
    {
        if (!HasKey || Key is not null || KeyProblem is not null) return;
        var r = SshKeys.Load(KeyPath, Passphrase, KeyOpener);
        Key = r.Key;
        KeyKind = r.Kind;
        KeyProblem = r.Error;
    }

    /// <summary>A fresh ConnectionInfo (auth methods can't be shared between connections). Throws
    /// <see cref="SshLoginException"/> when there is nothing to log in with.</summary>
    public ConnectionInfo CreateConnectionInfo(SshAuthLog log)
    {
        LoadKey();
        var methods = new List<AuthenticationMethod>(3);
        if (Key is not null)
            methods.Add(new TrackedAuthMethod(new PrivateKeyAuthenticationMethod(User, Key), r => log.Key = r));
        if (HasPassword)
        {
            // A pinned UTF-8 buffer (SSH.NET's byte[] overload), zeroed once the connection has authenticated — or failed.
            byte[] pw = SecureMemory.Utf8(Password);
            log.Secrets.Add(pw);
            methods.Add(new TrackedAuthMethod(new PasswordAuthenticationMethod(User, pw), r => log.Password = r));
            var kbd = new KeyboardInteractiveAuthenticationMethod(User);
            kbd.AuthenticationPrompt += (_, e) =>
            {
                // Hidden prompts ("Password:", "Password for x:") get the password; echoed ones (a user name, an OTP
                // code shown while typed) get nothing. A server that keeps asking gets empty answers after 3 rounds.
                int round = ++log.KbdRounds;
                foreach (var p in e.Prompts)
                    p.Response = round <= 3 && !p.IsEchoed ? Password : string.Empty;
            };
            methods.Add(new TrackedAuthMethod(kbd, r => log.Kbd = r));
        }
        if (methods.Count == 0)
            throw new SshLoginException(KeyProblem ?? "Enter a password or pick a key file.");

        var arr = methods.ToArray();
        var ci = UseProxy
            ? new ConnectionInfo(Host, Port, User, ProxyTypes.Socks5, ProxyHost, ProxyPort, string.Empty, string.Empty, arr)
            : new ConnectionInfo(Host, Port, User, arr);
        ci.Timeout = Timeout;
        return ci;
    }

    public void Dispose()
    {
        try { Key?.Dispose(); } catch { }
        Key = null;
    }
}

/// <summary>What each login method did during one connection attempt (filled on SSH.NET's thread).</summary>
public sealed class SshAuthLog
{
    public AuthenticationResult? Key { get; set; }
    public AuthenticationResult? Password { get; set; }
    public AuthenticationResult? Kbd { get; set; }
    public int KbdRounds { get; set; }
    internal List<byte[]> Secrets { get; } = new();

    /// <summary>The method that let us in, for the connected summary.</summary>
    public string Used =>
        Key == AuthenticationResult.Success ? "key"
        : Password == AuthenticationResult.Success ? "password"
        : Kbd == AuthenticationResult.Success ? "keyboard-interactive"
        : "login";

    public void Wipe()
    {
        foreach (var b in Secrets) SecureMemory.Zero(b);
        Secrets.Clear();
    }
}

/// <summary>Wraps an SSH.NET auth method to record its result; behaves exactly like the wrapped one.</summary>
internal sealed class TrackedAuthMethod : AuthenticationMethod
{
    private readonly AuthenticationMethod _inner;
    private readonly Action<AuthenticationResult> _record;

    public TrackedAuthMethod(AuthenticationMethod inner, Action<AuthenticationResult> record) : base(inner.Username)
    {
        _inner = inner;
        _record = record;
    }

    public override string Name => _inner.Name;

    public override AuthenticationResult Authenticate(Session session)
    {
        var r = _inner.Authenticate(session);
        AllowedAuthentications = _inner.AllowedAuthentications;   // what the server allows next (after a partial success)
        _record(r);
        return r;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>
/// Host-key verification: trust on first use, then pin (SHA-256). A changed key is refused (possible MITM) before any
/// password is sent. <see cref="Expected"/> (the SFTP connection) requires exactly the key the session saw.
/// </summary>
public sealed class SshHostKeyCheck
{
    public required string HostId { get; init; }
    public required string LegacyId { get; init; }
    public byte[]? Expected { get; init; }
    /// <summary>The new-pin notice (any thread).</summary>
    public Action<string>? Note { get; init; }
    public byte[]? Received { get; private set; }
    public string? Error { get; private set; }

    public static string PinId(string host, int port) => $"{host.Trim().TrimEnd('.').ToLowerInvariant()}:{port}";

    public void OnHostKey(object? sender, HostKeyEventArgs e)
    {
        byte[] hash = SHA256.HashData(e.HostKey);
        Received = hash;
        if (Expected is not null)
        {
            e.CanTrust = CryptographicOperations.FixedTimeEquals(hash, Expected);
            if (!e.CanTrust)
                Error = $"The host key changed between connections (now SHA256:{OpenSsh(hash)}). Possible MITM — refused.";
            return;
        }
        string fp = Convert.ToHexString(hash);
        var ps = ProfileService.Instance;
        var stored = ps.GetKnownHost(HostId) ?? ps.GetKnownHost(LegacyId);
        if (stored is not null)
        {
            if (string.Equals(stored, fp, StringComparison.OrdinalIgnoreCase))
            {
                e.CanTrust = true;
                if (ps.GetKnownHost(HostId) is null) ps.SetKnownHost(HostId, fp);   // migrate the legacy pin
            }
            else
            {
                e.CanTrust = false;
                Error = $"Host key mismatch for {HostId}: expected SHA256:{OpenSsh(stored)}, received SHA256:{OpenSsh(hash)} ({e.HostKeyName}). " +
                        "Possible MITM — refused, the password was not sent. If the key legitimately changed, remove its pin from the Echoes profile.";
            }
            return;
        }
        // Trust on first use, but never silently: the fingerprint goes to the terminal to compare with the server's own.
        e.CanTrust = true;
        ps.SetKnownHost(HostId, fp);
        Note?.Invoke($"# New host key for {HostId} ({e.HostKeyName}): SHA256:{OpenSsh(hash)}\n" +
                     "#   Pinned (trust on first use). Verify on the server: ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub\n");
    }

    public static string OpenSsh(byte[] sha256) => Convert.ToBase64String(sha256).TrimEnd('=');

    public static string OpenSsh(string hexPin)
    {
        try { return OpenSsh(Convert.FromHexString(hexPin)); }
        catch (FormatException) { return hexPin; }
    }
}

/// <summary>One clear sentence for each way a connection can fail.</summary>
public static partial class SshErrors
{
    public static string Explain(Exception ex, SshLogin login, SshAuthLog log, SshHostKeyCheck? hostKey = null)
    {
        if (hostKey?.Error is { } hk) return hk;
        if (ex is AggregateException { InnerException: { } inner }) ex = inner;
        switch (ex)
        {
            case SshLoginException: return ex.Message;
            case OperationCanceledException: return "Cancelled.";
            case SshAuthenticationException: return ExplainAuth(ex.Message, login, log);
            case ProxyException: return $"The proxy {SshText.Endpoint(login.ProxyHost, login.ProxyPort)} failed: {ex.Message}";
            case SocketException se: return ExplainSocket(se, login);
            case SshOperationTimeoutException: return $"Timed out connecting to {login.Endpoint}.";
            case SshConnectionException: return "The server closed the connection: " + ex.Message;
            default: return ex.Message;
        }
    }

    private static string ExplainSocket(SocketException se, SshLogin login)
    {
        string target = login.UseProxy ? $"the proxy {SshText.Endpoint(login.ProxyHost, login.ProxyPort)}" : login.Endpoint;
        return se.SocketErrorCode switch
        {
            SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain =>
                $"Host not found: {(login.UseProxy ? login.ProxyHost : login.Host)}.",
            SocketError.ConnectionRefused => $"Connection refused: nothing listens on {target}.",
            SocketError.TimedOut => $"Timed out connecting to {target}.",
            SocketError.NetworkUnreachable or SocketError.HostUnreachable => $"Can't reach {target}: {se.Message}",
            SocketError.ConnectionReset or SocketError.ConnectionAborted => $"The connection to {target} was reset.",
            _ => se.Message,
        };
    }

    [GeneratedRegex(@"\(([a-z0-9@.,\-]+)\)", RegexOptions.CultureInvariant)]
    private static partial Regex AllowedRx();

    /// <summary>Every reason, in the order the methods were tried: the key, then the password.</summary>
    public static string ExplainAuth(string message, SshLogin login, SshAuthLog log)
    {
        var parts = new List<string>(4);
        if (login.HasKey)
        {
            if (login.KeyProblem is { } kp) parts.Add(kp);
            else if (log.Key == AuthenticationResult.Failure) parts.Add("The server refused the key.");
            else if (log.Key is null) parts.Add("The server doesn't accept key login.");
        }
        if (login.HasPassword)
        {
            if (log.Password == AuthenticationResult.Failure || log.Kbd == AuthenticationResult.Failure)
                parts.Add("Wrong user name or password.");
            else if (log.Password is null && log.Kbd is null)
                parts.Add("The server doesn't accept password login.");
        }
        if (log.Key == AuthenticationResult.PartialSuccess || log.Password == AuthenticationResult.PartialSuccess || log.Kbd == AuthenticationResult.PartialSuccess)
            parts.Add("The server asks for one more login step that couldn't be completed.");
        if (message.StartsWith("No suitable authentication method", StringComparison.Ordinal) && AllowedRx().Match(message) is { Success: true } m)
            parts.Add($"It accepts: {m.Groups[1].Value.Replace(",", ", ")}.");
        if (parts.Count == 0) parts.Add(message);
        return string.Join(" ", parts);
    }
}

/// <summary>Small text helpers shared by the SSH tool.</summary>
public static class SshText
{
    public static string Endpoint(string host, int port) => Endpoint(host, (uint)Math.Max(0, port));

    public static string Endpoint(string host, uint port) =>
        host.Length == 0 ? $"*:{port}" : host.Contains(':') && !host.StartsWith('[') ? $"[{host}]:{port}" : $"{host}:{port}";

    /// <summary>True only if every address the listen host stands for is loopback (SSH.NET binds Any for "", else
    /// Dns.GetHostAddresses); anything unclear counts as exposed.</summary>
    public static bool IsLoopbackOnly(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        try
        {
            var addrs = System.Net.Dns.GetHostAddresses(host);
            return addrs.Length > 0 && Array.TrueForAll(addrs, a => System.Net.IPAddress.IsLoopback(a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a));
        }
        catch (Exception) { return false; }
    }

    public static string Bytes(long n)
    {
        if (n < 1024) return n + " B";
        double v = n;
        string[] u = { "KB", "MB", "GB", "TB", "PB" };
        int i = -1;
        do { v /= 1024; i++; } while (v >= 1024 && i < u.Length - 1);
        return v.ToString(v < 10 ? "0.0" : "0", System.Globalization.CultureInfo.InvariantCulture) + " " + u[i];
    }

    public static bool TryPort(string? text, bool allowZero, out int port)
    {
        port = 0;
        return int.TryParse(text?.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out port)
               && port <= 65535 && (port > 0 || allowZero);
    }
}
