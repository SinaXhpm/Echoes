#if STORE
using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;
using Echoes.Views;

namespace Echoes.Desktop;

// Mac App Store screenshots. .github/workflows/macos-appstore.yml starts the sandboxed test copy of the store build with
// ECHOES_STORE_SHOTS=1; once the window is up, this puts real tools on screen one scene after another, working against the
// real network (example.com, 1.1.1.1), and renders the window itself at 2x into a 2880x1800 picture (16:10, the size the store
// takes) on the app's own background. No screen recording is involved, so no permission is needed. The pictures land in the
// data folder's "store-shots"; "done.txt" marks the end. The shipped store build contains this, but it does nothing unless the
// variable is set.
internal static class StoreShots
{
    public static bool Requested => Environment.GetEnvironmentVariable("ECHOES_STORE_SHOTS") == "1";

    private const int CanvasW = 2880, CanvasH = 1800;
    private static readonly Color Background = Color.Parse("#0B0E14");   // Bg.App, dark
    private static readonly Color Frame = Color.Parse("#232B38");

    private static string _dir = string.Empty;
    private static MainWindow _window = null!;
    private static MainViewModel _main = null!;
    private static int _n;

    public static void Start(MainWindow window, MainViewModel main)
    {
        _window = window;
        _main = main;
        _dir = Path.Combine(AppStorage.UserDir(), "store-shots");
        _ = Task.Run(async () =>
        {
            try
            {
                Directory.CreateDirectory(_dir);
                foreach (string old in Directory.GetFiles(_dir)) File.Delete(old);
                await Task.Delay(4000).ConfigureAwait(false);
                await Ui(() => Application.Current!.RequestedThemeVariant = ThemeVariant.Dark);
                await Task.Delay(800).ConfigureAwait(false);

                await Run("doctor", Doctor);
                await Run("ping", Ping);
                await Run("share", Share);
                await Run("dns", Dns);
                await Run("tls", Tls);
                await Run("curl", Curl);
                await Run("password", Password);
            }
            catch (Exception ex) { File.AppendAllText(Path.Combine(_dir, "error.txt"), ex + "\n\n"); }
            finally
            {
                File.WriteAllText(Path.Combine(_dir, "done.txt"), string.Empty);
                Environment.Exit(0);
            }
        });
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
        await Ui(() => { vm.Target = "example.com"; vm.ToggleRunCommand.Execute(null); });
        await Until(() => !vm.IsRunning, 150_000);
        await Shot("doctor");
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

        // a phone on the same network opens the link, logs in with the PIN and writes; the owner answers
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
        await Post("/api/login", "{\"pin\":\"" + pin + "\",\"name\":\"iPhone (Safari)\"}");
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

    // Selects a tool in the sidebar (the TabControl "MainTabs", items tagged with the tool's name) and lets the page build.
    private static async Task Open(string tag)
    {
        await Ui(() =>
        {
            var tabs = _window.GetVisualDescendants().OfType<TabControl>().First(t => t.Name == "MainTabs");
            var item = tabs.Items.OfType<TabItem>().FirstOrDefault(i => i.Tag as string == tag)
                       ?? throw new InvalidOperationException("no sidebar entry " + tag);
            tabs.SelectedItem = item;
        });
        await Task.Delay(1500);
    }

    // The view of a tool on screen now.
    private static T ToolView<T>() where T : Control
        => _window.GetVisualDescendants().OfType<T>().FirstOrDefault(v => v.IsEffectivelyVisible)
           ?? throw new InvalidOperationException("no visible " + typeof(T).Name);

    // Renders the window's content at 2x and centers it on a 2880x1800 canvas with a thin frame.
    private static async Task Shot(string name)
    {
        await Task.Delay(1200);   // the last frame is drawn
        string id = (++_n).ToString("00");
        await Ui(() =>
        {
            var content = (Control)_window.Content!;
            var size = content.Bounds.Size;
            var px = new PixelSize((int)Math.Ceiling(size.Width * 2), (int)Math.Ceiling(size.Height * 2));
            using var window = new RenderTargetBitmap(px, new Vector(192, 192));
            window.Render(content);

            // fit inside the canvas with a margin (normally 1:1: the window is about 860 x 650 points)
            double scale = Math.Min(1.0, Math.Min((CanvasW - 240.0) / px.Width, (CanvasH - 240.0) / px.Height));
            double w = px.Width * scale, h = px.Height * scale;
            double x = Math.Round((CanvasW - w) / 2), y = Math.Round((CanvasH - h) / 2);
            using var canvas = new RenderTargetBitmap(new PixelSize(CanvasW, CanvasH), new Vector(96, 96));
            using (var ctx = canvas.CreateDrawingContext())
            {
                ctx.FillRectangle(new SolidColorBrush(Background), new Rect(0, 0, CanvasW, CanvasH));
                ctx.FillRectangle(new SolidColorBrush(Frame), new Rect(x - 2, y - 2, w + 4, h + 4), 22);
                ctx.DrawImage(window, new Rect(0, 0, px.Width, px.Height), new Rect(x, y, w, h));
            }
            canvas.Save(Path.Combine(_dir, $"{id}-{name}.png"), new PngBitmapEncoderOptions());
        });
    }
}
#endif
