using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// A request imported from the browser's developer tools: pasted into the Import panel, kept only sealed (its cookies and
// tokens are the user's), and sent as it is by the web check of its scheme and port while the site in the box is its own.
public partial class DoctorViewModel
{
    // ---- the Import panel
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowRequestLine))]
    private bool _isImportOpen;

    [ObservableProperty] private string _importText = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasImportError))]
    private string _importError = string.Empty;

    public bool HasImportError => ImportError.Length > 0;
    partial void OnImportTextChanged(string value) => ImportError = string.Empty;

    // ---- the imported request
    private DoctorRequest? _request;
    // the saved request when it can't be opened here (another device's key): kept as stored until one is imported or dropped
    private string? _unreadableRequest;

    public bool HasRequest => _request != null;
    public bool ShowRequestLine => _request != null && !IsImportOpen;

    /// <summary>The request is for the site in the box; another site never gets its cookies (it isn't sent then).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RequestLineText))]
    private bool _requestApplies = true;

    /// <summary>"POST example.com/api?… · 7 headers · 120-byte body", and why it isn't sent when it isn't.</summary>
    public string RequestLineText => _request == null ? ""
        : RequestApplies ? _request.Summary
        : $"{_request.Summary} — not sent: the site above is another one";

    /// <summary>The whole request, masked (the line's tooltip).</summary>
    public string RequestTip => _request?.Describe() ?? "";

    [RelayCommand]
    private async Task OpenImport()
    {
        ImportError = string.Empty;
        // a request already on the clipboard is filled in
        try
        {
            string? clip = await ClipboardHelper.GetTextAsync();
            if (DoctorRequest.LooksLikeRequest(clip)) ImportText = clip!.Trim();
        }
        catch { /* clipboard busy */ }
        IsImportOpen = true;
    }

    [RelayCommand]
    private void CloseImport()
    {
        IsImportOpen = false;
        ImportError = string.Empty;
        ImportText = string.Empty;
    }

    [RelayCommand]
    private async Task ImportRequest()
    {
        string text = ImportText;
        // a whole HAR file can be megabytes: read off the UI thread
        var (request, error) = await Task.Run(() => DoctorRequest.TryParse(text, out var r, out string e) ? (r, "") : (null, e));
        if (request == null)
        {
            ImportError = error;
            return;
        }
        UseRequest(request);
        IsImportOpen = false;
        ImportText = string.Empty;
    }

    [RelayCommand]
    private void DropRequest() => SetRequest(null);

    // The target becomes the request's site and path (not its query: that may carry a token), kept in the history the box
    // comes back from (the request is restored with it), and an address the cURL command pinned it to (--resolve) the
    // override IP.
    private void UseRequest(DoctorRequest request)
    {
        var u = request.Url;
        string page = u.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped);
        Target = page.EndsWith('/') && u.AbsolutePath == "/" ? page[..^1] : page;
        HistoryService.Instance.Add(HistoryKey, Target);
        if (request.ResolveTo is { } pin && DoctorIp.TryParseOverride(pin, out var ip, out _)) OverrideIp = ip!.ToString();
        SetRequest(request);
    }

    private void SetRequest(DoctorRequest? request)
    {
        _request = request;
        _unreadableRequest = null;
        OnPropertyChanged(nameof(HasRequest));
        OnPropertyChanged(nameof(ShowRequestLine));
        OnPropertyChanged(nameof(RequestTip));
        UpdateRequestApplies();
        OnPropertyChanged(nameof(RequestLineText));
        SchedulePersist();
    }

    partial void OnTargetChanged(string value) => UpdateRequestApplies();

    private void UpdateRequestApplies()
        => RequestApplies = _request == null
                            || (DoctorTarget.TryParse(Target, out var t, out _)
                                && string.Equals(t.AsciiHost, _request.Url.IdnHost.Trim('[', ']'), StringComparison.OrdinalIgnoreCase));

    // Loaded with the other settings: sealed JSON (an unreadable one is kept as it was stored).
    private void LoadRequest(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return;
        _request = DoctorRequest.FromJson(SecretProtector.Unprotect(stored));
        if (_request == null) _unreadableRequest = stored;
    }

    private string StoredRequest() => _unreadableRequest ?? (_request != null ? SecretProtector.Protect(_request.ToJson()) : "");
}
