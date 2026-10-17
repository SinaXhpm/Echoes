using CommunityToolkit.Mvvm.ComponentModel;
using Echoes.Helpers;
using Renci.SshNet;
using System;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;

namespace Echoes.ViewModels;

/// <summary>A port forward (-L / -R) with its live state. The spec is fixed; remove and add to change one.</summary>
public sealed partial class SshForwardRule : ObservableObject
{
    public SshForwardRule(SshForwardSpec spec) => Spec = spec;

    public SshForwardSpec Spec { get; }
    public string Flag => Spec.Flag;
    public bool IsRemote => Spec.Remote;

    /// <summary>"127.0.0.1:8080 → db.internal:5432".</summary>
    public string Title => $"{SshText.Endpoint(Spec.BindHost, _boundPort is uint b ? (int)b : Spec.BindPort)} → {SshText.Endpoint(Spec.TargetHost, Spec.TargetPort)}";

    /// <summary>Where each end lives.</summary>
    public string Direction => Spec.Remote ? "Server port → this device" : "This device → through the server";

    public const int Off = 0, Starting = 1, Active = 2, Failed = 3;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsActive), nameof(IsFailed), nameof(IsStarting))]
    private int _state;

    [ObservableProperty] private string _statusText = "Starts when connected";
    /// <summary>Listening beyond loopback (no authentication on a forwarded port).</summary>
    [ObservableProperty] private bool _isExposed;
    /// <summary>The last per-connection failure (target unreachable…), shown under a live forward.</summary>
    [ObservableProperty] [NotifyPropertyChangedFor(nameof(HasLastError))] private string _lastError = string.Empty;

    public bool IsActive => State == Active;
    public bool IsFailed => State == Failed;
    public bool IsStarting => State == Starting;
    public bool HasLastError => LastError.Length > 0;

    private uint? _boundPort;

    /// <summary>The live SSH.NET port and the session it belongs to (any thread reads, UI thread writes).</summary>
    internal ForwardedPort? Port { get; set; }
    internal object? Owner { get; set; }

    internal void SetStarting()
    {
        State = Starting;
        StatusText = "Starting…";
        LastError = string.Empty;
        IsExposed = false;
    }

    internal void SetActive(uint boundPort, bool exposed, string status)
    {
        _boundPort = boundPort;
        OnPropertyChanged(nameof(Title));
        State = Active;
        IsExposed = exposed;
        StatusText = status;
    }

    internal void SetFailed(string error)
    {
        Port = null;
        Owner = null;
        State = Failed;
        IsExposed = false;
        StatusText = error;
    }

    internal void SetOff()
    {
        Port = null;
        Owner = null;
        _boundPort = null;
        OnPropertyChanged(nameof(Title));
        State = Off;
        IsExposed = false;
        StatusText = "Starts when connected";
        LastError = string.Empty;
    }
}

/// <summary>One filesystem row of the Server view.</summary>
public sealed class SshDiskRow
{
    public SshDiskRow(SshDiskInfo d)
    {
        Mount = d.Mount;
        Filesystem = d.Filesystem;
        Percent = d.Percent;
        SizeText = $"{SshHealth.Kb(d.UsedKb)} of {SshHealth.Kb(d.SizeKb)}";
    }

    public string Mount { get; }
    public string Filesystem { get; }
    public double Percent { get; }
    public string PercentText => Percent.ToString("0", CultureInfo.InvariantCulture) + "%";
    public string SizeText { get; }
    public bool IsWarn => Percent >= 80 && Percent < 90;
    public bool IsHigh => Percent >= 90;
}

/// <summary>One "top by CPU" process row of the Server view.</summary>
public sealed class SshProcRow
{
    public SshProcRow(SshProcInfo p)
    {
        Pid = p.Pid;
        User = p.User;
        CpuText = p.Cpu.ToString("0.0", CultureInfo.InvariantCulture);
        MemText = p.Mem.ToString("0.0", CultureInfo.InvariantCulture);
        Command = p.Command;
    }

    public string Pid { get; }
    public string User { get; }
    public string CpuText { get; }
    public string MemText { get; }
    public string Command { get; }
}

/// <summary>A local file to upload: opened only when its turn comes.</summary>
public sealed record SshUploadItem(string Name, Func<Task<Stream>> Open, long? Size);

/// <summary>IProgress that runs the callback inline on the reporting thread (no SynchronizationContext hop).</summary>
internal sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value) => report(value);
}
