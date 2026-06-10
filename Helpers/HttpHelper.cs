using System;
using System.Net;
using System.Net.Http;

namespace Echoes.Helpers;

public static class HttpHelper
{
    public static HttpClient Create(
        string? proxyAddress = null,
        string? proxyUser = null,
        string? proxyPass = null,
        bool skipSslVerify = false,
        TimeSpan? timeout = null)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15)
        };

        if (!string.IsNullOrWhiteSpace(proxyAddress))
        {
            var proxy = new WebProxy(NormalizeProxy(proxyAddress));
            if (!string.IsNullOrWhiteSpace(proxyUser))
                proxy.Credentials = new NetworkCredential(proxyUser, proxyPass ?? string.Empty);
            handler.Proxy = proxy;
            handler.UseProxy = true;
        }

        if (skipSslVerify)
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;

        var client = new HttpClient(handler) { Timeout = timeout ?? TimeSpan.FromSeconds(15) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Echoes/0.2.5");
        return client;
    }

    public static string NormalizeProxy(string proxy)
    {
        proxy = proxy.Trim();
        if (proxy.Contains("://")) return proxy;

        if (proxy.Contains(":1080") || proxy.Contains(":1081") || proxy.Contains(":9050"))
            return "socks5://" + proxy;

        return "http://" + proxy;
    }
}
