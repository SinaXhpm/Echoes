using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>
/// One caught HTTP response in the shared response viewer (Views/Controls/ResponseView): its body pretty or raw (JSON /
/// XML formatted, an image shown, binary as hex), its status line and headers, copy and save. Doctor, Monitor, Check
/// Host, the proxy checker and a refused WebSocket handshake hand their responses to it. The body is laid out the first
/// time a viewer shows it (<see cref="LoadAsync"/>), off the UI thread, so a list of rows holding responses pays
/// nothing until one is opened.
/// </summary>
public sealed partial class HttpResponseViewModel : ObservableObject
{
    public HttpResponseViewModel(HttpResponseSnapshot response, string title)
    {
        Response = response;
        Title = title;
        _headDoc = CurlTextDocument.Create(response.HeadText(), CurlSyntax.None);
        _kindText = response.SizeText;
    }

    public HttpResponseSnapshot Response { get; }
    /// <summary>What it is the answer to ("HTTPS", "Frankfurt, DE", "the proxy at 1.2.3.4:8080").</summary>
    public string Title { get; }
    public string StatusLine => Response.StatusLine;
    /// <summary>"Title · HTTP/1.1 503 Service Unavailable": a picker's line.</summary>
    public string PickText => $"{Title} · {StatusLine}";
    public string? About => Response.About;
    public bool HasAbout => !string.IsNullOrEmpty(Response.About);

    private readonly CurlTextDocument _headDoc;
    private CurlTextDocument? _raw, _pretty;
    private string _text = string.Empty;
    private Task? _load;

    /// <summary>0 Body · 1 Headers.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowText), nameof(ShowImage), nameof(ShowEmpty), nameof(ShowPrettySwitch), nameof(ShowingHeaders))]
    private int _sectionIndex;

    /// <summary>0 Pretty · 1 Raw.</summary>
    [ObservableProperty] private int _bodyViewIndex;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowPrettySwitch))]
    private bool _prettyAvailable;

    /// <summary>What the code view shows: the body (pretty or raw) or the head.</summary>
    [ObservableProperty] private CurlTextDocument _document = CurlTextDocument.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowText), nameof(ShowImage), nameof(ShowEmpty))]
    private Bitmap? _image;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ShowText), nameof(ShowImage), nameof(ShowEmpty))]
    private bool _isLoading;

    [ObservableProperty] private string _kindText;
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasNote))]
    private string _note = string.Empty;
    public bool HasNote => Note.Length > 0;

    /// <summary>Long lines wrap: the viewer sits in narrow places (a flyout, a phone).</summary>
    [ObservableProperty] private bool _wrap = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFlash))]
    private string _flash = string.Empty;
    public bool HasFlash => Flash.Length > 0;

    public bool ShowingHeaders => SectionIndex == 1;
    public bool ShowText => SectionIndex == 1 || (!IsLoading && Image == null && _raw is { IsEmpty: false });
    public bool ShowImage => SectionIndex == 0 && Image != null;
    public bool ShowEmpty => SectionIndex == 0 && !IsLoading && Image == null && _raw is null or { IsEmpty: true };
    public bool ShowPrettySwitch => SectionIndex == 0 && PrettyAvailable;
    public bool CanSave => Response.Length > 0;

    partial void OnSectionIndexChanged(int value) => ShowCurrent();
    partial void OnBodyViewIndexChanged(int value) => ShowCurrent();

    private void ShowCurrent()
        => Document = SectionIndex == 1 ? _headDoc : (BodyViewIndex == 0 ? _pretty : null) ?? _raw ?? CurlTextDocument.Empty;

    /// <summary>Lays the body out (once; later calls wait for the first). UI thread.</summary>
    public Task LoadAsync() => _load ??= LoadCoreAsync();

    private async Task LoadCoreAsync()
    {
        IsLoading = true;
        var r = Response;
        string capText = FileHttpServer.HumanSize(r.Cap);
        ResponseBodyBuild b;
        try
        {
            b = r.Undecoded != null
                // still compressed (zstd …): shown as the bytes it is
                ? new ResponseBodyBuild(CurlBodyKind.Binary, string.Empty,
                                        CurlTextDocument.Create(CurlBody.HexDump(r.Body, r.Length), CurlSyntax.None), null, null,
                                        $"{r.Undecoded}-compressed · {FileHttpServer.HumanSize(r.Length)}",
                                        $"Still {r.Undecoded}-compressed: Echoes can't decode it, so it is shown as hex.")
                : await Task.Run(() => ResponseBodyBuilder.Build(r.Body, r.Length, r.ContentType, r.Cut,
                                                                  $"Showing the first {capText} — the body was longer (or broke off).",
                                                                  $"\n\n… [cut at {capText}]", null));
        }
        catch (Exception ex)
        {
            b = new ResponseBodyBuild(CurlBodyKind.Text, string.Empty, null, null, null, string.Empty, "Couldn't show the body: " + ex.Message);
        }
        _raw = b.Raw;
        _pretty = b.Pretty;
        _text = b.Text;
        KindText = b.KindText.Length > 0 ? b.KindText : r.SizeText;
        Note = b.Note;
        PrettyAvailable = b.Pretty != null;
        BodyViewIndex = PrettyAvailable ? 0 : 1;
        Image = b.Image;
        IsLoading = false;
        ShowCurrent();
        OnPropertyChanged(nameof(ShowText));
        OnPropertyChanged(nameof(ShowEmpty));
    }

    /// <summary>Lets an image preview's native pixels go now (a viewer dropped for good); the text stays.</summary>
    public void Release()
    {
        var image = Image;
        if (image is null) return;
        Image = null;
        // posted: the Image control lets go of it first (the renderer holds its own reference)
        Dispatcher.UIThread.Post(image.Dispose, DispatcherPriority.Background);
    }

    /// <summary>Copies what is shown: the head, or the body (pretty or raw).</summary>
    [RelayCommand]
    private async Task Copy()
    {
        string text = SectionIndex == 1 ? _headDoc.Text
            : (BodyViewIndex == 0 ? _pretty?.Text : null) ?? (_text.Length > 0 ? _text : _raw?.Text ?? string.Empty);
        if (text.Length == 0) return;
        await ClipboardHelper.SetTextAsync(text);
        ShowFlash(SectionIndex == 1 ? "Copied the headers" : "Copied the body");
    }

    public string SuggestedFileName => CurlBody.SuggestFileName(Response.Url ?? string.Empty, Response.ContentType, Response.Header("Content-Disposition"));

    /// <summary>Writes the body as it was kept (decompressed) — the view opens the stream with the platform's file picker.</summary>
    public async Task<string?> SaveAsync(Stream target)
    {
        try
        {
            await target.WriteAsync(Response.Body.AsMemory(0, Response.Length));
            await target.FlushAsync();
            return null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    public void ReportSaved(string? name, string? error)
        => ShowFlash(error != null ? "Couldn't save: " + error
                     : $"Saved {name}" + (Response.Cut ? $" (the first {FileHttpServer.HumanSize(Response.Length)})" : string.Empty));

    private int _flashTicket;

    private async void ShowFlash(string text)
    {
        int ticket = ++_flashTicket;
        Flash = text;
        await Task.Delay(2200);
        if (ticket == _flashTicket) Flash = string.Empty;
    }
}
