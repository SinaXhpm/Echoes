#if STORE
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Echoes.Helpers;

namespace Echoes.Desktop;

// A check of the Mac App Store build under the App Sandbox. .github/workflows/macos-appstore.yml signs a copy of the app
// ad hoc with the store's entitlements and starts it with ECHOES_STORE_SELFTEST=1; the app runs these checks before its
// window opens (what the sandbox can break: files, sockets, child processes, the single-instance socket), prints one line
// each ("STORETEST ok / FAIL / note"), shows its window, prints "STORETEST DONE failures=N" and exits. The shipped store
// build contains this code, but it does nothing unless that variable is set.
internal static class StoreSelfTest
{
    public static bool Requested => Environment.GetEnvironmentVariable("ECHOES_STORE_SELFTEST") == "1";

    private static int _failures;

    private static void Ok(string what, string detail = "") => Console.WriteLine($"STORETEST ok   {what}{(detail.Length > 0 ? ": " + detail : "")}");
    private static void Note(string what, string detail) => Console.WriteLine($"STORETEST note {what}: {detail}");
    private static void Fail(string what, string detail)
    {
        _failures++;
        Console.WriteLine($"STORETEST FAIL {what}: {detail}");
    }

    private static void Check(string what, Func<string> test)
    {
        try { Ok(what, test()); }
        catch (Exception ex) { Fail(what, ex.GetType().Name + ": " + ex.Message); }
    }

    /// <summary>The checks that need no window. Runs on the main thread before Avalonia starts.</summary>
    public static void RunHeadless()
    {
        Console.WriteLine("STORETEST start");

        string? container = Environment.GetEnvironmentVariable("APP_SANDBOX_CONTAINER_ID");
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Console.WriteLine($"STORETEST info HOME={home} container-id={(container ?? "(none)")}");

        Check("the process is sandboxed", () =>
        {
            // a sandboxed process has a container id and its $HOME inside ~/Library/Containers
            if (string.IsNullOrEmpty(container) && !home.Contains("/Library/Containers/", StringComparison.Ordinal))
                throw new InvalidOperationException("no container: the entitlements were not applied");
            string? real = MacSandbox.RealHome();
            if (real is null) throw new InvalidOperationException("the real home folder can't be told");
            // writing straight into the real home folder must be refused
            string probe = Path.Combine(real, ".echoes-sandbox-probe-" + Guid.NewGuid().ToString("N")[..6]);
            try
            {
                using (File.Create(probe)) { }
                File.Delete(probe);
                throw new InvalidOperationException("a file was created in " + real + ": there is no sandbox");
            }
            catch (UnauthorizedAccessException) { /* expected */ }
            return "real home " + real + " is closed";
        });

        Check("data folder: write, read, delete", () =>
        {
            string dir = AppStorage.UserDir();
            string file = Path.Combine(dir, ".storetest");
            File.WriteAllText(file, "ok");
            string back = File.ReadAllText(file);
            File.Delete(file);
            if (back != "ok") throw new InvalidOperationException("read back " + back);
            return dir.Replace(home, "~");
        });

        Check("instance lock file", () =>
        {
            string file = Path.Combine(AppStorage.UserDir(), ".storetest.lock");
            using var a = new FileStream(file, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            try
            {
                using var b = new FileStream(file, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                throw new InvalidOperationException("a second lock was granted");
            }
            catch (IOException) { /* expected: held */ }
            a.Dispose();
            File.Delete(file);
            return "held and refused";
        });

        Check("Downloads/Echoes (entitlement)", () =>
        {
            string folder = ShareInbox.DefaultFolder();
            if (!ShareInbox.IsWritableFolder(folder)) throw new InvalidOperationException(folder + " is not writable");
            return folder.Replace(MacSandbox.RealHome() ?? "?", "~");
        });

        Check("DNS lookup", () => Dns.GetHostAddresses("example.com") is { Length: > 0 } a ? a.Length + " address(es)" : throw new InvalidOperationException("no answer"));

        Check("TCP connect (network.client)", () =>
        {
            using var c = new TcpClient();
            if (!c.ConnectAsync("example.com", 443).Wait(15000)) throw new TimeoutException("no connection in 15 s");
            return "example.com:443";
        });

        Check("listen and connect on loopback (network.server)", () =>
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            try
            {
                int port = ((IPEndPoint)l.LocalEndpoint).Port;
                using var c = new TcpClient();
                if (!c.ConnectAsync(IPAddress.Loopback, port).Wait(5000)) throw new TimeoutException("no connection in 5 s");
                using var s = l.AcceptTcpClient();
                return "port " + port;
            }
            finally { l.Stop(); }
        });

        Check("UDP echo on loopback", () =>
        {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            using var client = new UdpClient();
            client.Send(new byte[] { 1, 2, 3 }, 3, new IPEndPoint(IPAddress.Loopback, port));
            server.Client.ReceiveTimeout = 3000;
            IPEndPoint any = new(IPAddress.Any, 0);
            byte[] got = server.Receive(ref any);
            return got.Length + " bytes";
        });

        // ping: the app's own probe, which falls back from ICMP to UDP by itself. Informational: a network may drop either.
        try
        {
            var r = IcmpPinger.SendAsync(IPAddress.Loopback, 3000, CancellationToken.None).GetAwaiter().GetResult();
            if (r.Success) Ok("ping 127.0.0.1", $"{r.Method}, {r.RoundtripMs} ms, TTL {r.Ttl}");
            else Note("ping 127.0.0.1", $"no reply ({r.Error})");
        }
        catch (Exception ex) { Note("ping 127.0.0.1", ex.GetType().Name + ": " + ex.Message); }

        // macOS hands every ICMP reply to every ICMP socket: a probe to an address nothing answers (TEST-NET-1), sent
        // together with one to loopback, must not end on loopback's reply (the replies are matched by identifier and
        // sequence). Sent through the ICMP datagram socket, not /sbin/ping: Method must say Icmp.
        Check("ICMP replies matched to their probe", () =>
        {
            var silent = IcmpPinger.SendAsync(IPAddress.Parse("192.0.2.1"), 1500, CancellationToken.None, 0, PingMethod.Icmp);
            var loop = IcmpPinger.SendAsync(IPAddress.Loopback, 1500, CancellationToken.None, 0, PingMethod.Icmp);
            var s = silent.GetAwaiter().GetResult();
            var l = loop.GetAwaiter().GetResult();
            if (s.Success) throw new InvalidOperationException("192.0.2.1 'answered': another probe's reply was taken");
            if (!l.Success) throw new InvalidOperationException("loopback didn't answer: " + l.Error);
            return $"192.0.2.1 silent ({s.Error}), loopback {l.RoundtripMs} ms, TTL {l.Ttl}";
        });
        try
        {
            var r = IcmpPinger.SendAsync(IPAddress.Parse("1.1.1.1"), 4000, CancellationToken.None).GetAwaiter().GetResult();
            if (r.Success) Ok("ping 1.1.1.1", $"{r.Method}, {r.RoundtripMs} ms, TTL {r.Ttl}");
            else Note("ping 1.1.1.1", $"no reply ({r.Method}): {r.Error}");
        }
        catch (Exception ex) { Note("ping 1.1.1.1", ex.GetType().Name + ": " + ex.Message); }

        // system tools the app starts (the cURL engine, sounds)
        Check("child process: /usr/bin/curl", () =>
        {
            var psi = new ProcessStartInfo("/usr/bin/curl") { RedirectStandardOutput = true, UseShellExecute = false };
            psi.ArgumentList.Add("--version");
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("not started");
            string first = (p.StandardOutput.ReadLine() ?? "").Trim();
            if (!p.WaitForExit(10000)) { try { p.Kill(); } catch { } throw new TimeoutException("curl did not finish"); }
            return first.Length > 40 ? first[..40] : first;
        });
        Check("child process: curl reaches the network", () =>
        {
            var psi = new ProcessStartInfo("/usr/bin/curl") { RedirectStandardOutput = true, UseShellExecute = false };
            foreach (string a in new[] { "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "https://example.com/" }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("not started");
            string code = p.StandardOutput.ReadToEnd().Trim();
            if (!p.WaitForExit(20000)) { try { p.Kill(); } catch { } throw new TimeoutException("curl did not finish"); }
            if (code != "200") throw new InvalidOperationException("HTTP " + code);
            return "HTTP 200";
        });
        try
        {
            var psi = new ProcessStartInfo("/sbin/ping") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            foreach (string a in new[] { "-c", "1", "-t", "3", "127.0.0.1" }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("not started");
            p.WaitForExit(8000);
            Ok("child process: /sbin/ping", "exit code " + p.ExitCode);
        }
        catch (Exception ex) { Note("child process: /sbin/ping", ex.GetType().Name + ": " + ex.Message); }
        Check("afplay is there", () => File.Exists("/usr/bin/afplay") ? "yes" : throw new FileNotFoundException("/usr/bin/afplay"));

        // the socket a second launch uses to bring the window up
        Check("single-instance socket", () =>
        {
            SingleInstance.StartListening();
            try
            {
                Thread.Sleep(500);
                if (!SingleInstance.TrySignalExisting()) throw new InvalidOperationException("the listener didn't answer");
                return "answered (socket name " + SingleInstance.PipeName.Length + " characters)";
            }
            finally { SingleInstance.StopListening(); }
        });

        Check("a file the user didn't pick is closed", () =>
        {
            // ~/.ssh is where a private key lives: the sandbox must keep Echoes out of it (a saved key path needs a new pick)
            string ssh = Path.Combine(MacSandbox.RealHome() ?? "/nonexistent", ".ssh");
            try { _ = Directory.GetFiles(ssh); }
            catch (UnauthorizedAccessException) { return "~/.ssh is closed"; }
            catch (DirectoryNotFoundException) { return "(no ~/.ssh here)"; }
            throw new InvalidOperationException("~/.ssh could be listed");
        });

        Console.WriteLine($"STORETEST headless checks done, failures={_failures}");
    }

    /// <summary>After the main window exists: the checks are done, print the verdict and leave.</summary>
    public static void Finish()
    {
        _ = Task.Run(async () =>
        {
            await Task.Delay(5000).ConfigureAwait(false);
            Console.WriteLine("STORETEST ok   the window opened (Avalonia and Skia run under the sandbox)");
            // what Echoes holds once its window is up (info, compared run to run)
            long managed = GC.GetTotalMemory(forceFullCollection: true);
            Note("memory with the window open", $"{Environment.WorkingSet / 1048576.0:0} MB resident, {managed / 1048576.0:0.0} MB managed");
            Console.WriteLine($"STORETEST DONE failures={_failures}");
            Console.Out.Flush();
            Environment.Exit(_failures == 0 ? 0 : 1);
        });
    }
}
#endif
