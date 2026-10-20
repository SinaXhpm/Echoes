using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;
using Echoes.Views;

namespace Echoes.iOS;

// A smoke test of what the shared tools need from the platform: storage, DNS, TCP, ICMP, HTTPS, a TLS server, loopback
// sockets, child processes, the sound and screen-on helpers, and every tool opening in the touch shell (with a picture of
// each, in the data folder's "tour"). It runs only when the app is started with ECHOES_SELFTEST=1 (CI starts it that way
// on a simulator, .github/workflows/ios.yml) and writes one line per check, "ok" or "FAIL", to the console and to
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

        async Task Check(string name, Func<CancellationToken, Task<string>> body, int seconds = 30)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
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

        // Loopback answers by itself, so these show whether this platform can send ICMP echoes and the UDP fallback at all.
        await Check("icmp echo to loopback", async ct =>
        {
            var r = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, ct, 0, PingMethod.Icmp).ConfigureAwait(false);
            if (!r.Success) throw new InvalidOperationException($"{r.Error}{(r.PermissionDenied ? " (not permitted)" : "")}");
            return $"{r.RoundtripMs} ms";
        });

        await Check("udp ping to loopback", async ct =>
        {
            var r = await IcmpPinger.SendAsync(IPAddress.Loopback, 3000, ct, 0, PingMethod.Udp).ConfigureAwait(false);
            if (!r.Success) throw new InvalidOperationException($"{r.Error}");
            return $"{r.RoundtripMs} ms";
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

        await Check("network interfaces", _ =>
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            var up = nics.Where(n => n.OperationalStatus == OperationalStatus.Up).ToList();
            var v4 = up.SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address)
                       .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)).Take(3).ToList();
            string Safe(Func<string> f) { try { return f(); } catch (Exception ex) { return $"unavailable ({ex.GetType().Name})"; } }
            string gw = Safe(() => string.Join(",", up.SelectMany(n => n.GetIPProperties().GatewayAddresses).Select(g => g.Address).Take(2)));
            string dns = Safe(() => string.Join(",", up.SelectMany(n => n.GetIPProperties().DnsAddresses).Select(d => d.ToString()).Take(2)));
            string conns = Safe(() => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Length + " TCP connections");
            return Task.FromResult($"{nics.Length} interfaces, {up.Count} up; IPv4 {string.Join(", ", v4)}; gateway {gw}; dns {dns}; {conns}");
        });

        // The whole share hub on this platform: HTTPS with its own certificate, the page, a PIN login and a chat message.
        await Check("share hub: HTTPS page, PIN login and chat", async ct =>
        {
            var cert = await Task.Run(ShareTls.LoadOrCreate, ct).ConfigureAwait(false);
            string inbox = Path.Combine(AppStorage.UserDir(), "selftest-inbox");
            Directory.CreateDirectory(inbox);
            int port;
            using (var probe = new TcpListener(IPAddress.Loopback, 0)) { probe.Start(); port = ((IPEndPoint)probe.LocalEndpoint).Port; }
            var hub = new ShareHub(new ShareHubOptions
            {
                Bind = IPAddress.Loopback, Port = port, Cert = cert, RequirePin = true, Pin = "12345678", InboxFolder = inbox, PartFolder = "",
                HostName = "iOS self-test", Items = () => Array.Empty<SharedItem>(),
            }, new NullSink());
            hub.Start();
            try
            {
                using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };
                using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
                string origin = $"https://127.0.0.1:{port}";
                HttpRequestMessage Req(HttpMethod m, string path, string? json = null)
                {
                    var r = new HttpRequestMessage(m, origin + path);
                    r.Headers.Add("X-Echoes", "1");
                    r.Headers.Add("Origin", origin);
                    if (json is not null) r.Content = new StringContent(json, Encoding.UTF8, "application/json");
                    return r;
                }
                string page = await http.GetStringAsync(origin + "/", ct).ConfigureAwait(false);
                if (!page.Contains("<html", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("no page came back");
                using var login = await http.SendAsync(Req(HttpMethod.Post, "/api/login", "{\"pin\":\"12345678\",\"name\":\"iOS test\"}"), ct).ConfigureAwait(false);
                if (!login.IsSuccessStatusCode) throw new InvalidOperationException($"login answered {(int)login.StatusCode}");
                using var send = await http.SendAsync(Req(HttpMethod.Post, "/api/send", "{\"text\":\"hello from the self-test\"}"), ct).ConfigureAwait(false);
                if (!send.IsSuccessStatusCode) throw new InvalidOperationException($"send answered {(int)send.StatusCode}");
                using var poll = await http.SendAsync(Req(HttpMethod.Get, "/api/poll?since=0"), ct).ConfigureAwait(false);
                string body = await poll.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                if (!body.Contains("hello from the self-test", StringComparison.Ordinal)) throw new InvalidOperationException("the message didn't come back: " + body[..Math.Min(120, body.Length)]);
                return $"https on port {port}: page {page.Length} chars, logged in, a message went through";
            }
            finally { hub.Stop(); }
        });
        await Check("crack time (the String Lab card)", _ =>
            Task.FromResult($"128 bits vs one GPU: {CrackTime.Describe(128, 1e11)}"));

        // The Files app shows Documents only: the received files go there, the app's own data stays out of it.
        await Check("storage layout (app data, and the folder the Files app shows)", _ =>
        {
            string data = AppStorage.UserDir(), received = ShareInbox.DefaultFolder();
            if (!data.Contains("/Library/Application Support/", StringComparison.Ordinal))
                throw new InvalidOperationException("the app's data isn't in Library/Application Support: " + data);
            if (!received.EndsWith("/Documents/Received", StringComparison.Ordinal))
                throw new InvalidOperationException("received files aren't in Documents/Received: " + received);
            Directory.CreateDirectory(received);
            // a path an earlier run saved (the container folder changes with an update) is moved into this container;
            // nothing outside the received folder can be reached that way
            const string old = "/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000/Documents";
            if (ShareInbox.RebaseIos(old + "/Received/a.txt") != Path.Combine(received, "a.txt"))
                throw new InvalidOperationException("a saved path wasn't moved into this container: " + ShareInbox.RebaseIos(old + "/Received/a.txt"));
            if (ShareInbox.RebaseIos(old + "/.config/Echoes/profile.json") is not null) throw new InvalidOperationException("a path outside Received was accepted");
            if (ShareInbox.RebaseIos(old + "/Received/../Echoes.txt") is not null) throw new InvalidOperationException("a path climbing out of Received was accepted");
            return Task.FromResult($"app data in {data[data.IndexOf("/Library/", StringComparison.Ordinal)..]}, received files in {received[received.IndexOf("/Documents/", StringComparison.Ordinal)..]}");
        });

        // A CI runner has no sound output, so "couldn't start" is only reported; a crash or an exception would fail.
        await Check("alert sound (info)", _ =>
        {
            bool started = new IosSoundPlayer().Play(SoundTones.CreatePcm(AlertTone.Up, 10), SoundTones.SampleRate);
            return Task.FromResult(started ? "AVAudioPlayer started it" : "AVAudioPlayer couldn't start it (no sound output here?)");
        });

        await Check("the screen stays on while something runs", async ct =>
        {
            BackgroundGuard.Acquire("self-test");
            await Task.Delay(700, ct).ConfigureAwait(false);
            bool on = await Dispatcher.UIThread.InvokeAsync(() => UIKit.UIApplication.SharedApplication.IdleTimerDisabled);
            BackgroundGuard.Release();
            await Task.Delay(700, ct).ConfigureAwait(false);
            bool off = !await Dispatcher.UIThread.InvokeAsync(() => UIKit.UIApplication.SharedApplication.IdleTimerDisabled);
            if (!on || !off) throw new InvalidOperationException($"the screen stayed on: {on} while running, released after: {off}");
            return "on while a job runs, back to normal after it";
        });

        // Opens every tool in the touch shell, one after another, like a person tapping through the drawer. A tool whose
        // view or view-model can't be built here shows "failed to load" (ToolViews.Fill) and writes to the crash log.
        // A picture of each page is saved to the data folder's "tour" (CI keeps them).
        await Check("every tool opens in the touch shell", async ct =>
        {
            var shell = await Dispatcher.UIThread.InvokeAsync(() =>
                (Application.Current?.ApplicationLifetime as ISingleViewApplicationLifetime)?.MainView as MobileShellView);
            if (shell is null) throw new InvalidOperationException("the touch shell isn't there");
            var (nav, pages) = await Dispatcher.UIThread.InvokeAsync(() => (shell.FindControl<ListBox>("Nav"), shell.FindControl<Carousel>("Pages")));
            if (nav is null || pages is null) throw new InvalidOperationException("the drawer list or the pages are missing");

            string shots = Path.Combine(AppStorage.UserDir(), "tour");
            Directory.CreateDirectory(shots);
            foreach (string stale in Directory.GetFiles(shots, "*.png")) File.Delete(stale);
            string crashLog = AppStorage.UserPath("echoes-crash.log");
            long logged = File.Exists(crashLog) ? new FileInfo(crashLog).Length : 0;

            int count = await Dispatcher.UIThread.InvokeAsync(() => nav.ItemCount);
            var opened = new List<string>();
            var problems = new List<string>();
            for (int i = 0; i < count; i++)
            {
                int at = i;
                string tag = await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    nav.SelectedIndex = at;
                    return (nav.SelectedItem as ListBoxItem)?.Tag as string ?? "?";
                });
                await Task.Delay(1200, ct).ConfigureAwait(false);   // layout, and the refresh that runs once the page is drawn
                string? problem = await Dispatcher.UIThread.InvokeAsync(() => Inspect(shell, pages, at, tag));
                string file = Path.Combine(shots, $"{at + 1:00}-{tag.ToLowerInvariant().Replace(' ', '-')}.png");
                await Dispatcher.UIThread.InvokeAsync(() => Shot(shell, file));
                if (problem is null) opened.Add(tag); else problems.Add($"{tag}: {problem}");
            }
            // The About box: in a store build it has no update section, and a phone gets the Copy log button.
            if (await Dispatcher.UIThread.InvokeAsync(() => shell.DataContext as MainViewModel) is { } main)
            {
                await Dispatcher.UIThread.InvokeAsync(() => main.OpenAboutCommand.Execute(null));
                await Task.Delay(1000, ct).ConfigureAwait(false);
                await Dispatcher.UIThread.InvokeAsync(() => Shot(shell, Path.Combine(shots, $"{count + 1:00}-about.png")));
                if (main.ShowUpdates) problems.Add("ABOUT: the update section is shown in an App Store build");
                if (!main.CanCopyLog) problems.Add("ABOUT: no Copy log button on a phone");
                await Dispatcher.UIThread.InvokeAsync(() => main.CloseAboutCommand.Execute(null));
            }
            foreach (string entry in NewCrashEntries(crashLog, logged)) problems.Add("crash log: " + entry);
            if (problems.Count > 0) throw new InvalidOperationException(string.Join(" | ", problems));
            return $"{opened.Count} of {count} opened: {string.Join(", ", opened)}";
        }, seconds: 300);

        Line($"SELFTEST DONE failures={failures}");
        return failures;
    }

    // UI thread: what the page of one drawer entry shows now, or what is wrong with it.
    private static string? Inspect(MobileShellView shell, Carousel pages, int index, string tag)
    {
        static string? Page(Control? child, string name, bool needsSize)
        {
            if (child is null) return $"{name} is empty";
            if (child is TextBlock { Text: { } text } && text.Contains("failed to load", StringComparison.Ordinal)) return text;
            if (needsSize && (child.Bounds.Width < 1 || child.Bounds.Height < 1)) return $"{name} has no size ({child.Bounds.Width:0}x{child.Bounds.Height:0})";
            return null;
        }
        if (tag == "DATA")   // History and Backup share one entry (two tabs: only the first one is on screen)
            return Page(shell.FindControl<Decorator>("HistoryHost")?.Child as Control, "History", true)
                ?? Page(shell.FindControl<Decorator>("BackupHost")?.Child as Control, "Backup", false);
        return index < pages.ItemCount && pages.Items[index] is Decorator host ? Page(host.Child as Control, tag, true) : $"no page for {tag}";
    }

    // UI thread: a picture of the whole shell (the app bar and the page) at twice the size, for the CI artifacts.
    private static void Shot(Control shell, string file)
    {
        try
        {
            int w = (int)shell.Bounds.Width, h = (int)shell.Bounds.Height;
            if (w < 1 || h < 1) return;
            using var bitmap = new RenderTargetBitmap(new PixelSize(w * 2, h * 2), new Vector(192, 192));
            bitmap.Render(shell);
            bitmap.Save(file, PngBitmapEncoderOptions.Default);
        }
        catch (Exception ex) { Line($"SELFTEST note: no picture of {Path.GetFileName(file)} ({ex.GetType().Name}: {ex.Message})"); }
    }

    // What the crash log gained after a position: the first line of each entry names the place and the exception.
    private static List<string> NewCrashEntries(string file, long from)
    {
        var found = new List<string>();
        try
        {
            if (!File.Exists(file)) return found;
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length <= from) return found;
            fs.Seek(from, SeekOrigin.Begin);
            using var reader = new StreamReader(fs, Encoding.UTF8);
            while (reader.ReadLine() is { } line)
                if (line.StartsWith("[20", StringComparison.Ordinal) && found.Count < 8) found.Add(line.Length > 240 ? line[..240] : line);
        }
        catch { }
        return found;
    }
}

// The hub reports here; the test only needs it to exist.
file sealed class NullSink : IShareHubSink
{
    public void OnLog(string line) { }
    public void OnMessage(ShareMessage message) { }
    public void OnChatCleared() { }
    public void OnUploadStarted(ShareUpload upload) { }
    public void OnUploadFinished(ShareUpload upload, string? path, string? error) { }
    public void OnDownload(string itemId, long bytes, bool complete) { }
}
