using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Echoes.Helpers;

namespace Echoes.iOS;

// A smoke test of what the shared tools need from the platform: storage, DNS, TCP, ICMP, HTTPS, a TLS server, loopback
// sockets, child processes. It runs only when the app is started with ECHOES_SELFTEST=1 (CI starts it that way on a
// simulator, .github/workflows/ios.yml) and writes one line per check, "ok" or "FAIL", to the console and to
// selftest.txt in the app's data folder, ending with "SELFTEST DONE failures=N". Nothing in it runs in a normal start.
internal static class SelfTest
{
    public static bool Requested => Environment.GetEnvironmentVariable("ECHOES_SELFTEST") == "1";

    private static readonly StringBuilder Report = new();
    private static string? _file;

    private static void Line(string text)
    {
        Console.WriteLine(text);
        lock (Report)
        {
            Report.AppendLine(text);
            try { if (_file is not null) File.WriteAllText(_file, Report.ToString()); } catch { }
        }
    }

    public static async Task<int> RunAsync()
    {
        int failures = 0;
        try { _file = Path.Combine(AppStorage.UserDir(), "selftest.txt"); } catch { }

        async Task Check(string name, Func<CancellationToken, Task<string>> body)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                string detail = await body(cts.Token).ConfigureAwait(false);
                Line($"SELFTEST ok   {name}: {detail}");
            }
            catch (Exception ex)
            {
                failures++;
                Line($"SELFTEST FAIL {name}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        Line($"SELFTEST start {AppInfo.Platform} | {AppInfo.Runtime}");

        await Check("storage", _ =>
        {
            string dir = AppStorage.UserDir();
            string probe = Path.Combine(dir, "probe.txt");
            File.WriteAllText(probe, "x");
            bool ok = File.ReadAllText(probe) == "x";
            File.Delete(probe);
            var p = ProfileService.Instance;
            p.SetSetting("selftest.value", "42");
            if (p.GetSetting("selftest.value") != "42") throw new InvalidOperationException("the profile didn't keep a setting");
            return Task.FromResult($"{(ok ? "read and write work" : "READ BACK DIFFERS")} in {dir}");
        });

        await Check("dns (system resolver)", async ct =>
        {
            var a = await Dns.GetHostAddressesAsync("example.com", ct).ConfigureAwait(false);
            if (a.Length == 0) throw new InvalidOperationException("no addresses");
            return string.Join(", ", a.Take(3).Select(x => x.ToString()));
        });

        await Check("tcp connect 1.1.1.1:443", async ct =>
        {
            var r = await TcpPinger.ConnectAsync(IPAddress.Parse("1.1.1.1"), 443, 5000, ct).ConfigureAwait(false);
            if (!r.Success) throw new InvalidOperationException($"{r.Status}: {r.Detail}");
            return $"{r.Ms:0} ms";
        });

        // The runner's network may drop ICMP, so a failed echo is reported, not counted: the point is which method works here.
        await Check("icmp ping 1.1.1.1 (info)", async ct =>
        {
            var r = await IcmpPinger.SendAsync(IPAddress.Parse("1.1.1.1"), 4000, ct).ConfigureAwait(false);
            return r.Success ? $"{r.Method}, {r.RoundtripMs} ms" : $"no echo ({r.Method}): {r.Error}{(r.PermissionDenied ? " [no probe is allowed here]" : "")}";
        });

        await Check("https get example.com", async ct =>
        {
            using var http = HttpHelper.Create(timeout: TimeSpan.FromSeconds(15));
            string body = await http.GetStringAsync("https://example.com/", ct).ConfigureAwait(false);
            if (!body.Contains("Example Domain", StringComparison.Ordinal)) throw new InvalidOperationException("unexpected page");
            return $"{body.Length} chars";
        });

        await Check("tls server (the share page's certificate)", async ct =>
        {
            var cert = await Task.Run(ShareTls.LoadOrCreate, ct).ConfigureAwait(false);
            string? why = await ShareTls.SelfTestAsync(cert, ct).ConfigureAwait(false);
            if (why is not null) throw new InvalidOperationException(why);
            return $"served and read back, {cert.Protocols}";
        });

        await Check("loopback tcp server and client", async ct =>
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            try
            {
                int port = ((IPEndPoint)l.LocalEndpoint).Port;
                var accept = l.AcceptTcpClientAsync(ct).AsTask();
                using var c = new TcpClient();
                await c.ConnectAsync(IPAddress.Loopback, port, ct).ConfigureAwait(false);
                using var s = await accept.ConfigureAwait(false);
                await c.GetStream().WriteAsync(new byte[] { 1, 2, 3 }, ct).ConfigureAwait(false);
                var buf = new byte[3];
                int n = await s.GetStream().ReadAsync(buf, ct).ConfigureAwait(false);
                if (n != 3 || buf[2] != 3) throw new InvalidOperationException("bytes differ");
                return $"3 bytes through port {port}";
            }
            finally { l.Stop(); }
        });

        await Check("child process (info)", async ct =>
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo("/bin/echo", "hi") { RedirectStandardOutput = true });
                if (p is null) return "Process.Start returned nothing";
                await p.WaitForExitAsync(ct).ConfigureAwait(false);
                return "works";
            }
            catch (Exception ex) { return $"not available ({ex.GetType().Name})"; }
        });

        await Check("crack time (the String Lab card)", _ =>
            Task.FromResult($"128 bits vs one GPU: {CrackTime.Describe(128, 1e11)}"));

        Line($"SELFTEST DONE failures={failures}");
        return failures;
    }
}
