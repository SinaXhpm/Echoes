#if STORESHOTS
using System.Net.Http;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using Echoes.Helpers;
using Echoes.ViewModels;
using Echoes.Views;

namespace Echoes.iOS;

// App Store screenshots. CI (.github/workflows/ios-screenshots.yml) starts the app with ECHOES_SHOTS=1 on an iPhone 6.9"
// and an iPad 13" simulator; the app puts real tools on screen, one scene after another, working against the real
// network (example.com, 1.1.1.1). For every scene it drops ready-NN-name.txt in the data folder's "shots" and waits for
// taken-NN.txt: the workflow takes a native-size screenshot of the simulator (xcrun simctl io screenshot) in between, so
// the pictures have the real status bar and are exactly the size the store wants. Compiled only with -p:StoreShots=true:
// the shipped app has none of this.
internal static class StoreShots
{
    public static bool Requested => Environment.GetEnvironmentVariable("ECHOES_SHOTS") == "1";

    private static string _dir = string.Empty;
    private static MobileShellView _shell = null!;
    private static MainViewModel _main = null!;
    private static int _n;

    public static async Task RunAsync()
    {
        _dir = Path.Combine(AppStorage.UserDir(), "shots");
        Directory.CreateDirectory(_dir);
        foreach (string old in Directory.GetFiles(_dir)) File.Delete(old);
        try
        {
            _shell = await Dispatcher.UIThread.InvokeAsync(() =>
                (Application.Current?.ApplicationLifetime as ISingleViewApplicationLifetime)?.MainView as MobileShellView)
                ?? throw new InvalidOperationException("the touch shell isn't there");
            _main = await Dispatcher.UIThread.InvokeAsync(() => _shell.DataContext as MainViewModel)
                ?? throw new InvalidOperationException("the shell has no view-model");

            await Run("doctor", Doctor);
            await Run("menu", Menu);
            await Run("ping", Ping);
            await Run("speed", Speed);
            await Run("monitor", Monitor);
            await Run("share", Share);
            await Run("dns", Dns);
            await Run("tls", Tls);
            await Run("curl", Curl);
            await Run("password", Password);
        }
        catch (Exception ex) { File.WriteAllText(Path.Combine(_dir, "error.txt"), ex.ToString()); }
        finally { File.WriteAllText(Path.Combine(_dir, "done.txt"), string.Empty); }
    }

    // A scene that fails is written down and skipped: the others still get their pictures.
    private static async Task Run(string name, Func<Task> scene)
    {
        try { await scene(); }
        catch (Exception ex) { File.AppendAllText(Path.Combine(_dir, "error.txt"), $"{name}: {ex}\n\n"); }
    }

    // ---------------------------------------------------------------- scenes

    private static async Task Doctor()
    {
        await Open("DOCTOR");
        var vm = _main.DoctorVM;
        // an iPad's tall page shows each check's steps too (Details), instead of half a page of nothing
        bool wide = await Ui(() => _shell.Bounds.Width > 700);
        await Ui(() => { vm.ShowDetails = wide; vm.Target = "example.com"; vm.ToggleRunCommand.Execute(null); });
        await Until(() => !vm.IsRunning, 150_000);
        await Shot("doctor");
    }

    // The drawer open over the Doctor's result: every tool at a glance.
    private static async Task Menu()
    {
        await Ui(() => _shell.FindControl<SplitView>("Split")!.IsPaneOpen = true);
        await Task.Delay(1000);
        await Shot("menu");
        await Ui(() => _shell.FindControl<SplitView>("Split")!.IsPaneOpen = false);
        await Task.Delay(600);
    }

    // The test caught mid-download, the gauge live, on a file server near the runner: Cloudflare refuses tests from the
    // data-centre addresses CI runs on (HTTP 403, in the download or the upload), which put an error on the picture.
    private static async Task Speed()
    {
        await Open("SPEED TEST");
        var vm = await Ui(() => (SpeedTestViewModel)ToolView<SpeedTestView>().DataContext!);
        await Ui(() =>
        {
            if (SpeedTestDestinations.FindCurated("lw-wdc") is { } near) vm.SelectedDestination = near;
            vm.ToggleCommand.Execute(null);
        });
        await Until(() => vm.DownloadProgress >= 0.6 || !vm.IsRunning, 150_000);
        await Shot("speed");
        await Ui(() => { if (vm.IsRunning) vm.ToggleCommand.Execute(null); });
        await Until(() => !vm.IsRunning, 30_000);
    }

    // A few public sites checked every 5 s for about 40 s: the list shows their state, latency and a short graph.
    private static async Task Monitor()
    {
        await Open("MONITOR");
        var vm = _main.MonitorVM;
        await Ui(() =>
        {
            vm.NewTarget = "example.com\n1.1.1.1\nhttps://www.apple.com\ngithub.com:443\n8.8.8.8";
            vm.AddTargetsCommand.Execute(null);
            if (!vm.IsMonitoring) vm.ToggleMonitorCommand.Execute(null);
        });
        await Task.Delay(40_000);
        await Shot("monitor");
        await Ui(() => { if (vm.IsMonitoring) vm.ToggleMonitorCommand.Execute(null); });
    }

    private static async Task Ping()
    {
        await Open("PING");
        var vm = _main.PingVM;
        await Ui(() =>
        {
            vm.ResetOptionsCommand.Execute(null);
            vm.ModeIndex = 3;            // TCP: works on any network
            vm.IntervalSec = 0.3m;
            vm.TcpPortText = "443";
            vm.TargetHost = "1.1.1.1";
            vm.TogglePingCommand.Execute(null);
        });
        await Until(() => vm.LogItems.Count >= 40, 60_000);
        await Shot("ping");
        await Ui(() => { if (vm.IsPinging) vm.TogglePingCommand.Execute(null); });
    }

    private static async Task Share()
    {
        await Open("WEB SERVER");
        var vm = _main.WebServerVM;
        await Ui(() => { vm.Port = 8080; vm.ModeIndex = 0; vm.FocusProbe = () => true; vm.ToggleServerCommand.Execute(null); });
        await Until(() => vm.IsRunning, 40_000);

        // a laptop on the same network opens the link, logs in with the PIN and writes; the owner answers
        string pin = await Ui(() => vm.Pin);
        using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        string origin = "https://127.0.0.1:8080";
        async Task Post(string path, string json)
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, origin + path);
            req.Headers.Add("X-Echoes", "1");
            req.Headers.Add("Origin", origin);
            req.Content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = await http.SendAsync(req).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
        }
        await Post("/api/login", "{\"pin\":\"" + pin + "\",\"name\":\"MacBook Air (Safari)\"}");
        await Post("/api/send", "{\"text\":\"Hi! I opened the link from the QR code.\"}");
        await Ui(() => { vm.ChatDraft = "Welcome. You can send me files here too."; vm.SendChatCommand.Execute(null); });
        await Post("/api/send", "{\"text\":\"Got it, thanks!\"}");
        await Until(() => vm.ChatItems.Count >= 3, 20_000);
        await Shot("share");
        await Ui(() => vm.ToggleServerCommand.Execute(null));
    }

    private static async Task Dns()
    {
        await Open("DNS");
        var vm = _main.DnsVM;
        await Ui(() =>
        {
            vm.ModeIndex = DnsViewModel.ModeLookup;
            vm.DnsServersText = "https://1.1.1.1/dns-query\n8.8.8.8";
            vm.TypeA = true; vm.TypeAAAA = true; vm.TypeMX = true;
            vm.DomainName = "example.com";
        });
        await Dispatcher.UIThread.InvokeAsync(() => vm.RunLookupCommand.ExecuteAsync(null));
        await Until(() => !vm.IsWorking, 60_000);
        await Shot("dns");
    }

    private static async Task Tls()
    {
        await Open("TLS");
        var vm = await Ui(() => (TlsViewModel)ToolView<TlsView>().DataContext!);
        await Ui(() => vm.Target = "example.com");
        await Dispatcher.UIThread.InvokeAsync(() => vm.InspectCommand.ExecuteAsync(null));
        await Until(() => !vm.IsBusy, 60_000);
        await Shot("tls");
    }

    private static async Task Curl()
    {
        await Open("CURL");
        var vm = _main.CurlVM;
        await Ui(() => { vm.UseDotNetEngine = true; vm.HttpMethod = "GET"; vm.Url = "https://example.com/"; });
        await Dispatcher.UIThread.InvokeAsync(() => vm.ToggleCurlCommand.ExecuteAsync(null));
        await Until(() => !vm.IsWorking, 60_000);
        await Ui(() => vm.ResponseTabIndex = 2);   // Timing: where the time went (DNS, connect, TLS, first byte)
        await Task.Delay(800);
        await Shot("curl");
    }

    private static async Task Password()
    {
        await Open("STRING LAB");
        var vm = _main.StringTool;
        await Ui(() =>
        {
            vm.CategoryIndex = 3;     // Dev
            vm.DevToolIndex = 5;      // Generate
            vm.GenerateLength = 20;
            vm.GenerateCount = 3;
            vm.GenerateCommand.Execute("password");
        });
        await Until(() => vm.GenerateOutput.Length > 0, 10_000);
        await Shot("password");
    }

    // ---------------------------------------------------------------- helpers

    private static Task<T> Ui<T>(Func<T> f) => Dispatcher.UIThread.InvokeAsync(f).GetTask();

    private static Task Ui(Action a) => Dispatcher.UIThread.InvokeAsync(a).GetTask();

    private static async Task Until(Func<bool> condition, int timeoutMs)
    {
        for (int waited = 0; waited < timeoutMs; waited += 300)
        {
            if (await Ui(condition)) return;
            await Task.Delay(300);
        }
    }

    // Selects a tool in the drawer list (by the Tag the shell gives it) and waits for the page to be built and drawn.
    private static async Task Open(string tag)
    {
        await Ui(() =>
        {
            var nav = _shell.FindControl<ListBox>("Nav")!;
            for (int i = 0; i < nav.ItemCount; i++)
                if ((nav.Items[i] as ListBoxItem)?.Tag as string == tag) { nav.SelectedIndex = i; return; }
            throw new InvalidOperationException("no drawer entry " + tag);
        });
        await Task.Delay(1500);
    }

    // The view of the tool that is on screen now (the host Decorator of the selected page).
    private static T ToolView<T>() where T : Control
    {
        var nav = _shell.FindControl<ListBox>("Nav")!;
        var pages = _shell.FindControl<Carousel>("Pages")!;
        return (pages.Items[nav.SelectedIndex] is Decorator host ? ToolViews.ViewIn(host) : null) as T ?? throw new InvalidOperationException("the page isn't a " + typeof(T).Name);
    }

    // Tells the workflow the scene is on screen and waits (at most a minute) until it has taken the screenshot.
    private static async Task Shot(string name)
    {
        string id = (++_n).ToString("00");
        await Task.Delay(1200);   // the last frame is drawn
        File.WriteAllText(Path.Combine(_dir, $"ready-{id}-{name}.txt"), string.Empty);
        string taken = Path.Combine(_dir, $"taken-{id}.txt");
        for (int i = 0; i < 120 && !File.Exists(taken); i++) await Task.Delay(500);
    }
}
#endif
