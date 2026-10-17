using System;

namespace Echoes.ViewModels;

// The WEB tab: renders the ACTUAL response body the request returned — through the same proxy / override IP / interface —
// instead of letting the OS WebView do its own fresh navigation to the URL (which would ignore all of that).
public partial class CurlViewModel
{
    // WebBaseUri (direct requests only) lets the document's relative styles/images resolve against the original URL. The
    // view (code-behind) renders via NativeWebView.NavigateToString when RenderWebRequested fires.
    public string WebHtml { get; private set; } = string.Empty;
    public Uri? WebBaseUri { get; private set; }
    public event Action? RenderWebRequested;

    // WebView2's NavigateToString caps around 2 MB; keep the rendered document under that (the full body stays in Body).
    private const int WebRenderCap = 2_000_000;

    // The response is untrusted (it may come via -k, an override IP or a hostile proxy), so it's rendered inert: a CSP
    // injected ahead of the whole document blocks every script (inline, on*= handlers, javascript: URLs), frames, plugins,
    // forms and fetch/XHR, and a page can only tighten it, never loosen it; the view also cancels any navigation away from
    // the rendered string (and on WebView2 turns script off entirely). Sub-resources are the other leak: the WebView fetches
    // them itself — directly / via the OS proxy, NOT through this request's proxy, override IP or NIC — so for a routed
    // request nothing may load from the network (and no base URI is given). A plain direct request may still pull
    // styles/images/fonts so pages stay readable.
    private const string CspRouted =
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; form-action 'none'; base-uri 'none'";
    private const string CspDirect =
        "default-src 'none'; style-src 'unsafe-inline' http: https:; img-src data: http: https:; " +
        "font-src data: http: https:; form-action 'none'; base-uri 'none'";

    private void RenderWeb(string? body, string? url, bool routed)
    {
        string doc = string.IsNullOrEmpty(body) ? string.Empty : (body.Length > WebRenderCap ? body[..WebRenderCap] : body);
        WebHtml = PrepareWebDocument(doc, routed);
        WebBaseUri = !routed && Uri.TryCreate(url, UriKind.Absolute, out var u) &&
                     (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps) ? u : null;
        RenderWebRequested?.Invoke();
    }

    // The CSP goes at offset 0, before every byte the server sent (a regex-matched prologue disagreed with the HTML parser
    // on \v / U+00A0 / "<!-->" and let a script run before the <meta>). Our own doctype keeps standards mode. The native
    // WebView composites over black, so a page that declares no background of its own gets the browser default white
    // first (a page's own background still overrides it). For a routed request DNS prefetching is switched off too: CSP
    // doesn't govern <link rel=dns-prefetch>.
    private static string PrepareWebDocument(string html, bool routed)
    {
        if (string.IsNullOrEmpty(html)) return html;
        return "<!doctype html><meta http-equiv=\"Content-Security-Policy\" content=\"" + (routed ? CspRouted : CspDirect) + "\">"
             + (routed ? "<meta http-equiv=\"x-dns-prefetch-control\" content=\"off\">" : "")
             + "<style>html{background:#ffffff;color:#111111}</style>" + html;
    }
}
