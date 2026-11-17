using System.IO;
using Avalonia.Media.Imaging;
using Echoes.Helpers;

namespace Echoes.ViewModels;

/// <summary>A body made ready to show: its kind, its text as read, the raw and pretty documents (null when there is
/// none), an image's preview, a one-line label ("JSON · 1.2 KB") and a note about it.</summary>
public sealed record ResponseBodyBuild(CurlBodyKind Kind, string Text, CurlTextDocument? Raw, CurlTextDocument? Pretty, Bitmap? Image,
                                       string KindText, string Note);

/// <summary>
/// Lays a response body out for the viewers (cURL's response, and the shared one in Views/Controls/ResponseView): sniffed
/// (JSON, XML, HTML, text, image, binary), decoded with its charset, pretty-printed when that changes it, an image decoded
/// for a preview (never a decompression bomb's full size), anything else as hex. Off the UI thread.
/// </summary>
public static class ResponseBodyBuilder
{
    /// <summary>Largest image the preview decodes (~128 MB of pixels): a few KB of PNG can declare 50000×50000.</summary>
    public const long MaxPreviewPixels = 32_000_000;
    /// <summary>Wider images are decoded scaled down to this (a 6000×4000 photo took 96 MB to show ~650 px of it).</summary>
    public const int MaxPreviewWidth = 2560;

    /// <param name="truncated">There was more than <paramref name="len"/> bytes: no pretty view (it would be of half a
    /// document), <paramref name="cutMarker"/> closes the text, and <paramref name="cutNote"/> is the note.</param>
    /// <param name="decodedFrom">The encoding the body was decompressed from, for the note.</param>
    public static ResponseBodyBuild Build(byte[] buf, int len, string? contentType, bool truncated, string? cutNote, string? cutMarker,
                                          string? decodedFrom)
    {
        var kind = CurlBody.Sniff(buf, len, contentType);
        string size = FileHttpServer.HumanSize(len);
        string media = CurlBody.MediaTypeOf(contentType);
        string note = truncated && cutNote != null ? cutNote : string.Empty;
        if (decodedFrom != null && note.Length == 0) note = $"Decoded from {decodedFrom} (the server compressed it)";
        switch (kind)
        {
            case CurlBodyKind.Empty:
                return new ResponseBodyBuild(kind, string.Empty, null, null, null, "Empty body", "The response has no body.");
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
                    return new ResponseBodyBuild(kind, string.Empty, null, null, image, $"Image · {media} · {width}×{height} · {size}", note);
                }
                if (tooBig is not null && note.Length == 0)
                    note = $"Image too large to preview ({tooBig} pixels): shown as hex. Save keeps the original bytes.";
                goto case CurlBodyKind.Binary;
            }
            case CurlBodyKind.Binary:
            {
                var hex = CurlTextDocument.Create(CurlBody.HexDump(buf, len), CurlSyntax.None);
                return new ResponseBodyBuild(kind, string.Empty, hex, null, null, $"Binary · {(media.Length > 0 ? media : "unknown type")} · {size}",
                                             note.Length > 0 ? note : "Binary content, shown as hex — Save keeps the original bytes.");
            }
        }
        string text = CurlBody.Decode(buf, len, CurlBody.CharsetOf(contentType), truncated: false);
        if (truncated && cutMarker != null) text += cutMarker;
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
        return new ResponseBodyBuild(kind, text, raw, pretty, null, $"{label} · {size}", note);
    }
}
