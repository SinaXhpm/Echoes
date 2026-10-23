using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

// The response: status, timing, body (pretty / raw, search, image, hex), headers, cookies, redirects, logs, save / copy.
public partial class CurlViewModel
{
    // ---- state
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowEmptyResponse), nameof(ShowWaiting))]
    private bool _hasResponse;
    [ObservableProperty] private string _statusText = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusSuccess), nameof(StatusInfo), nameof(StatusWarning), nameof(StatusDanger), nameof(StatusNeutral))]
    private string _statusKind = string.Empty;
    public bool StatusSuccess => StatusKind == "success";
    public bool StatusInfo => StatusKind == "info";
    public bool StatusWarning => StatusKind == "warning";
    public bool StatusDanger => StatusKind == "danger";
    public bool StatusNeutral => StatusKind == "neutral";
    public bool ShowEmptyResponse => !HasResponse && !IsWorking;
    public bool ShowWaiting => !HasResponse && IsWorking;
    /// <summary>The status line has something to say (on narrow widths it takes a line of its own only then).</summary>
    public bool ShowSummary => HasResponse || IsWorking || HasFlash;
    partial void OnIsWorkingChanged(bool value)
    {
        OnPropertyChanged(nameof(ShowEmptyResponse));
        OnPropertyChanged(nameof(ShowWaiting));
        OnPropertyChanged(nameof(ShowSummary));
    }
    partial void OnHasResponseChanged(bool value) => OnPropertyChanged(nameof(ShowSummary));

    /// <summary>A response arrived (an error without one shows no size).</summary>
    [ObservableProperty] private bool _hasBodySize;
    [ObservableProperty] private string _engineText = string.Empty;
    [ObservableProperty] private string _resultNote = string.Empty;
    public bool HasResultNote => ResultNote.Length > 0;
    partial void OnResultNoteChanged(string value) => OnPropertyChanged(nameof(HasResultNote));

    // ---- the one error (why it failed, and what to do)
    [ObservableProperty] private string _errorTitle = string.Empty;
    [ObservableProperty] private string _errorDetail = string.Empty;
    [ObservableProperty] private string _errorHint = string.Empty;
    public bool HasError => ErrorTitle.Length > 0;
    public bool HasErrorHint => ErrorHint.Length > 0;
    partial void OnErrorTitleChanged(string value) => OnPropertyChanged(nameof(HasError));
    partial void OnErrorHintChanged(string value) => OnPropertyChanged(nameof(HasErrorHint));

    // ---- body
    [ObservableProperty] private CurlTextDocument _bodyDocument = CurlTextDocument.Empty;
    private CurlTextDocument? _rawDoc, _prettyDoc;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowBodyText))]
    private bool _prettyAvailable;
    /// <summary>0 Pretty · 1 Raw.</summary>
    [ObservableProperty] private int _bodyViewIndex;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasImage), nameof(ShowBodyText), nameof(ShowBodyToolbar))]
    private Bitmap? _bodyImage;
    public bool HasImage => BodyImage != null;
    public bool ShowBodyToolbar => HasBodyText || HasImage;

    // A replaced preview releases its native (Skia) pixels now rather than at finalization, so a run of image responses
    // doesn't pile them up. Posted: the Image control lets go of the old one first (the renderer holds its own reference).
    partial void OnBodyImageChanged(Bitmap? oldValue, Bitmap? newValue)
    {
        if (oldValue is not null && !ReferenceEquals(oldValue, newValue))
            Avalonia.Threading.Dispatcher.UIThread.Post(oldValue.Dispose, Avalonia.Threading.DispatcherPriority.Background);
    }

    /// <summary>Largest image the preview decodes (~128 MB of pixels): a few KB of PNG can declare 50000×50000.</summary>
    private const long MaxPreviewPixels = 32_000_000;
    /// <summary>Wider images are decoded scaled down to this (a 6000×4000 photo took 96 MB to show ~650 px of it).</summary>
    private const int MaxPreviewWidth = 2560;
    [ObservableProperty] private string _bodyKindText = string.Empty;
    [ObservableProperty] private string _bodyNote = string.Empty;
    public bool HasBodyNote => BodyNote.Length > 0;
    partial void OnBodyNoteChanged(string value) => OnPropertyChanged(nameof(HasBodyNote));
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowBodyText), nameof(CanCopyBody), nameof(ShowBodyToolbar))]
    private bool _hasBodyText;
    public bool ShowBodyText => HasBodyText && !HasImage;
    [ObservableProperty] private bool _wrapBody;
    [ObservableProperty] private string _searchText = string.Empty;

    private byte[] _bodyBytes = Array.Empty<byte>();
    private int _bodyLength;
    private bool _bodyTruncated;
    private string? _bodyContentType, _bodyDisposition;
    private string _finalUrl = string.Empty;
    private string _bodyText = string.Empty;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanCopyBody))]
    private bool _canSaveBody;
    public bool CanCopyBody => HasBodyText;

    partial void OnBodyViewIndexChanged(int value) => BodyDocument = (value == 0 ? _prettyDoc : null) ?? _rawDoc ?? CurlTextDocument.Empty;

    // ---- headers / cookies / redirects / timing
    [ObservableProperty] private IReadOnlyList<CurlHeaderRow> _responseHeaders = Array.Empty<CurlHeaderRow>();
    [ObservableProperty] private IReadOnlyList<CurlHeaderRow> _requestHeadersSent = Array.Empty<CurlHeaderRow>();
    [ObservableProperty] private IReadOnlyList<CurlCookie> _responseCookies = Array.Empty<CurlCookie>();
    /// <summary>0 Response · 1 Request (as sent) · 2 Cookies.</summary>
    [ObservableProperty] private int _headersViewIndex;
    public string ResponseHeadersBadge => ResponseHeaders.Count > 0 ? ResponseHeaders.Count.ToString() : string.Empty;
    public string CookiesCountText => ResponseCookies.Count > 0 ? $"Cookies ({ResponseCookies.Count})" : "Cookies";
    public bool HeadersShowResponse => HeadersViewIndex == 0;
    public bool HeadersShowRequest => HeadersViewIndex == 1;
    public bool HeadersShowCookies => HeadersViewIndex == 2;
    public bool NoCookies => ResponseCookies.Count == 0;
    partial void OnResponseHeadersChanged(IReadOnlyList<CurlHeaderRow> value) => OnPropertyChanged(nameof(ResponseHeadersBadge));
    partial void OnResponseCookiesChanged(IReadOnlyList<CurlCookie> value)
    {
        OnPropertyChanged(nameof(CookiesCountText));
        OnPropertyChanged(nameof(NoCookies));
    }
    partial void OnHeadersViewIndexChanged(int value)
    {
        OnPropertyChanged(nameof(HeadersShowResponse));
        OnPropertyChanged(nameof(HeadersShowRequest));
        OnPropertyChanged(nameof(HeadersShowCookies));
    }

    [ObservableProperty] private IReadOnlyList<CurlTimingRow> _timingRows = Array.Empty<CurlTimingRow>();
    [ObservableProperty] private string _timingTotalText = string.Empty;
    [ObservableProperty] private string _timingMetaText = string.Empty;
    [ObservableProperty] private IReadOnlyList<CurlHopRow> _hops = Array.Empty<CurlHopRow>();
    public bool HasHops => Hops.Count > 1;
    public bool HasTiming => TimingRows.Count > 0;
    partial void OnHopsChanged(IReadOnlyList<CurlHopRow> value) => OnPropertyChanged(nameof(HasHops));
    partial void OnTimingRowsChanged(IReadOnlyList<CurlTimingRow> value) => OnPropertyChanged(nameof(HasTiming));

    [ObservableProperty] private string _fullLog = string.Empty;
    [ObservableProperty] private string _sslLog = string.Empty;

    // ================================================================== lifecycle

    private void BeginResponse()
    {
        ClearResponse();
        SectionIndex = 1;
    }

    private void ClearResponse()
    {
        HasBodySize = false;
        HasResponse = false;
        StatusText = string.Empty;
        StatusKind = string.Empty;
        EngineText = string.Empty;
        ResultNote = string.Empty;
        ErrorTitle = ErrorDetail = ErrorHint = string.Empty;
        _rawDoc = _prettyDoc = null;
        PrettyAvailable = false;
        BodyDocument = CurlTextDocument.Empty;
        BodyImage = null;
        HasBodyText = false;
        BodyKindText = string.Empty;
        BodyNote = string.Empty;
        CanSaveBody = false;
        _bodyBytes = Array.Empty<byte>();
        _bodyLength = 0;
        _bodyText = string.Empty;
        ResponseHeaders = Array.Empty<CurlHeaderRow>();
        RequestHeadersSent = Array.Empty<CurlHeaderRow>();
        ResponseCookies = Array.Empty<CurlCookie>();
        TimingRows = Array.Empty<CurlTimingRow>();
        TimingTotalText = TimingMetaText = string.Empty;
        Hops = Array.Empty<CurlHopRow>();
        FullLog = string.Empty;
        RenderWeb(null, null, routed: false);
    }

    private void ShowStopped()
    {
        HasResponse = true;
        StatusText = "Stopped";
        StatusKind = "neutral";
        ErrorTitle = "Stopped";
        ErrorDetail = "The request was stopped before a response arrived.";
        ErrorHint = string.Empty;
    }

    private void ShowFailure(string title, string detail, string? hint)
    {
        HasResponse = true;
        StatusText = "Error";
        StatusKind = "danger";
        ErrorTitle = title;
        ErrorDetail = detail;
        ErrorHint = hint ?? string.Empty;
    }

    private sealed record BodyBuild(CurlBodyKind Kind, string Text, CurlTextDocument? Raw, CurlTextDocument? Pretty, Bitmap? Image, string KindText, string Note);

    private async Task ShowResultAsync(CurlResult res, CurlRequest req, int gen)
    {
        EngineText = res.Engine;
        ResultNote = string.Join(" · ", res.Notes);
        FullLog = res.FullLog;

        if (res.Cancelled) { ShowStopped(); return; }

        if (res.Responded)
        {
            HasResponse = true;
            StatusText = res.Reason.Length > 0 ? $"{res.Status} {res.Reason}" : res.Status.ToString();
            StatusKind = res.Status switch { < 300 => "success", < 400 => "info", < 500 => "warning", _ => "danger" };
        }
        if (res.Failed)
        {
            if (!res.Responded) ShowFailure(res.ErrorTitle!, res.ErrorDetail ?? string.Empty, res.ErrorHint);
            else
            {
                // a response arrived, but the transfer still failed (too many redirects, cut short, …)
                ErrorTitle = res.ErrorTitle!;
                ErrorDetail = res.ErrorDetail ?? string.Empty;
                ErrorHint = res.ErrorHint ?? string.Empty;
            }
        }

        ResponseHeaders = res.Headers.Select(h => new CurlHeaderRow(h.Name, h.Value)).ToList();
        RequestHeadersSent = res.RequestHeaders.Select(h => new CurlHeaderRow(h.Name, h.Value)).ToList();
        ResponseCookies = CurlBody.SetCookies(res.Headers);
        HeadersViewIndex = 0;
        Hops = res.Hops.Select(h => new CurlHopRow(h.Status.ToString(), h.Method, h.Url,
            h.Status switch { < 300 => "success", < 400 => "info", < 500 => "warning", _ => "danger" })).ToList();
        BuildTiming(res);

        HasBodySize = res.Responded;
        ResponseSizeText = res.Responded ? FileHttpServer.HumanSize(res.BodyLength) + (res.Truncated ? "+" : string.Empty) : "—";

        // the body: decoded, pretty-printed and indexed off the UI thread
        _bodyBytes = res.Body;
        _bodyLength = res.BodyLength;
        _bodyTruncated = res.Truncated;
        _bodyContentType = res.Header("Content-Type");
        _bodyDisposition = res.Header("Content-Disposition");
        _finalUrl = res.FinalUrl.Length > 0 ? res.FinalUrl : req.Url;
        CanSaveBody = res.Responded && res.BodyLength > 0;
        if (!res.Responded) return;

        var buf = res.Body;
        int len = res.BodyLength;
        bool truncated = res.Truncated;
        string? ct = _bodyContentType;
        string? decoded = res.ContentEncodingDecoded;
        BodyBuild b;
        try { b = await Task.Run(() => BuildBody(buf, len, truncated, ct, decoded)); }
        catch (Exception ex) { b = new BodyBuild(CurlBodyKind.Text, string.Empty, null, null, null, string.Empty, "Couldn't show the body: " + ex.Message); }
        if (gen != _runGen) return;

        _rawDoc = b.Raw;
        _prettyDoc = b.Pretty;
        _bodyText = b.Text;
        PrettyAvailable = b.Pretty != null;
        BodyViewIndex = PrettyAvailable ? 0 : 1;
        BodyDocument = (PrettyAvailable ? _prettyDoc : _rawDoc) ?? CurlTextDocument.Empty;
        BodyImage = b.Image;
        HasBodyText = b.Raw != null && !b.Raw.IsEmpty;
        BodyKindText = b.KindText;
        BodyNote = b.Note;
        ResponseTabIndex = 0;

        bool routed = req.Proxy != null || req.OverrideIp != null || req.InterfaceIp != null;
        RenderWeb(b.Kind is CurlBodyKind.Html or CurlBodyKind.Text or CurlBodyKind.Xml or CurlBodyKind.Json ? b.Text : null, _finalUrl, routed);
    }

    private static BodyBuild BuildBody(byte[] buf, int len, bool truncated, string? contentType, string? decodedFrom)
    {
        var kind = CurlBody.Sniff(buf, len, contentType);
        string size = FileHttpServer.HumanSize(len);
        string media = CurlBody.MediaTypeOf(contentType);
        string note = truncated ? $"Showing the first {CurlEngine.MaxResponseBytes / (1024 * 1024)} MB — the response was larger. Save keeps what arrived." : string.Empty;
        if (decodedFrom != null && note.Length == 0) note = $"Decoded from {decodedFrom} (the server compressed it)";
        switch (kind)
        {
            case CurlBodyKind.Empty:
                return new BodyBuild(kind, string.Empty, null, null, null, "Empty body", "The response has no body.");
            case CurlBodyKind.Image:
            {
                Bitmap? image = null;
                string? tooBig = null;
                int width = 0, height = 0;
                try
                {
                    // The dimensions first, from the header only: decoding a decompression bomb would take gigabytes.
                    using (var probe = new MemoryStream(buf, 0, len, writable: false))
                    using (var codec = SkiaSharp.SKCodec.Create(probe))
                        if (codec is not null)
                        {
                            (width, height) = (codec.Info.Width, codec.Info.Height);
                            if ((long)width * height > MaxPreviewPixels) tooBig = $"{width}×{height}";
                        }
                    if (tooBig is null)
                    {
                        // the preview only ever shrinks it to fit: a big photo is decoded at a preview width, not in full
                        using var ms = new MemoryStream(buf, 0, len, writable: false);
                        image = width > MaxPreviewWidth ? Bitmap.DecodeToWidth(ms, MaxPreviewWidth, BitmapInterpolationMode.MediumQuality) : new Bitmap(ms);
                    }
                }
                catch { /* not decodable: fall back to the hex view */ }
                if (image != null)
                {
                    if (width <= 0) (width, height) = (image.PixelSize.Width, image.PixelSize.Height);
                    return new BodyBuild(kind, string.Empty, null, null, image, $"Image · {media} · {width}×{height} · {size}", note);
                }
                if (tooBig is not null && note.Length == 0)
                    note = $"Image too large to preview ({tooBig} pixels): shown as hex. Save keeps the original bytes.";
                goto case CurlBodyKind.Binary;
            }
            case CurlBodyKind.Binary:
            {
                var hex = CurlTextDocument.Create(CurlBody.HexDump(buf, len), CurlSyntax.None);
                return new BodyBuild(kind, string.Empty, hex, null, null, $"Binary · {(media.Length > 0 ? media : "unknown type")} · {size}",
                                     note.Length > 0 ? note : "Binary content, shown as hex — Save keeps the original bytes.");
            }
        }
        string text = CurlBody.Decode(buf, len, CurlBody.CharsetOf(contentType), truncated);
        var syntax = kind switch { CurlBodyKind.Json => CurlSyntax.Json, CurlBodyKind.Xml or CurlBodyKind.Html => CurlSyntax.Xml, _ => CurlSyntax.None };
        var raw = CurlTextDocument.Create(text, syntax);
        CurlTextDocument? pretty = null;
        if (!truncated)
        {
            string? p = kind switch
            {
                CurlBodyKind.Json => CurlBody.PrettyJson(buf, len),
                CurlBodyKind.Xml => CurlBody.PrettyXml(text),
                _ => null,
            };
            if (p != null && p != text) pretty = CurlTextDocument.Create(p, syntax);
        }
        string label = kind switch { CurlBodyKind.Json => "JSON", CurlBodyKind.Xml => "XML", CurlBodyKind.Html => "HTML", _ => media.Length > 0 ? media : "Text" };
        return new BodyBuild(kind, text, raw, pretty, null, $"{label} · {size}", note);
    }

    private void BuildTiming(CurlResult res)
    {
        var t = res.Timing;
        var phases = new List<(string Label, double? Ms, string Kind)>
        {
            ("DNS lookup", t.DnsMs, "dns"),
            ("TCP connect", t.ConnectMs, "connect"),
            ("TLS handshake", t.TlsMs, "tls"),
            ("Waiting (TTFB)", t.WaitMs, "wait"),
            ("Download", t.DownloadMs, "download"),
        };
        double sum = phases.Sum(p => p.Ms ?? 0);
        double total = Math.Max(Math.Max(sum, t.TotalMs), 0.001);
        var rows = new List<CurlTimingRow>();
        double at = 0;
        foreach (var (label, ms, kind) in phases)
        {
            if (ms is not double v) continue;
            rows.Add(new CurlTimingRow(label, FormatMs(v), at / total, Math.Max(v / total, 0), kind));
            at += v;
        }
        TimingRows = t.TotalMs > 0 || sum > 0 ? rows : Array.Empty<CurlTimingRow>();
        TimingTotalText = t.TotalMs > 0 ? "Total " + FormatMs(t.TotalMs) + (t.Requests > 1 ? $" · {t.Requests} requests (redirects included)" : string.Empty) : string.Empty;
        var meta = new List<string>();
        if (res.RemoteAddress is { Length: > 0 } ra) meta.Add("Remote " + ra);
        if (res.HttpVersion.Length > 0) meta.Add(res.HttpVersion);
        if (res.Engine.Length > 0) meta.Add(res.Engine);
        TimingMetaText = string.Join(" · ", meta);
    }

    // ================================================================== copy / save

    [RelayCommand]
    private async Task CopyBody()
    {
        string text = (BodyViewIndex == 0 ? _prettyDoc : null)?.Text ?? _bodyText;
        if (string.IsNullOrEmpty(text)) text = BodyDocument.Text;
        if (string.IsNullOrEmpty(text)) return;
        await ClipboardHelper.SetTextAsync(text);
        Flash("Copied the body");
    }

    [RelayCommand]
    private async Task CopyHeaders()
    {
        IEnumerable<CurlHeaderRow> rows = HeadersViewIndex == 1 ? RequestHeadersSent : ResponseHeaders;
        string text = HeadersViewIndex == 2
            ? string.Join("\n", ResponseCookies.Select(c => $"{c.Name}={c.Value}" + (c.Attributes.Length > 0 ? "; " + c.Attributes.Replace(" · ", "; ") : "")))
            : (HeadersViewIndex == 0 && StatusText.Length > 0 ? StatusText + "\n" : string.Empty) + string.Join("\n", rows.Select(h => $"{h.Name}: {h.Value}"));
        if (text.Length == 0) return;
        await ClipboardHelper.SetTextAsync(text);
        Flash("Copied the headers");
    }

    public string SuggestedBodyFileName => CurlBody.SuggestFileName(_finalUrl, _bodyContentType, _bodyDisposition);

    /// <summary>Writes the body exactly as it arrived (decompressed) — the view opens the stream with the platform's
    /// file picker (desktop dialog, Android's storage provider).</summary>
    public async Task<string?> SaveBodyAsync(Stream target)
    {
        try
        {
            await target.WriteAsync(_bodyBytes.AsMemory(0, _bodyLength));
            await target.FlushAsync();
            return null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    public void ReportSaved(string? name, string? error)
    {
        if (error != null) Flash("Couldn't save: " + error);
        else Flash($"Saved {name}" + (_bodyTruncated ? " (the first 16 MB)" : string.Empty));
    }

    // ================================================================== transient feedback

    [ObservableProperty] private string _flashText = string.Empty;
    public bool HasFlash => FlashText.Length > 0;
    partial void OnFlashTextChanged(string value)
    {
        OnPropertyChanged(nameof(HasFlash));
        OnPropertyChanged(nameof(ShowSummary));
    }
    private int _flashTicket;

    private async void Flash(string text)
    {
        int ticket = ++_flashTicket;
        FlashText = text;
        await Task.Delay(2200);
        if (ticket == _flashTicket) FlashText = string.Empty;
    }
}
