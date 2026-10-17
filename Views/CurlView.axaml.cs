using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Platform;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Echoes.Helpers;
using Echoes.ViewModels;

namespace Echoes.Views
{
    public partial class CurlView : UserControl
    {
        private CurlViewModel? _vm;
        private bool _adapterReady;

        // The WEB tab shows an untrusted response. Its CSP (see CurlViewModel.RenderWeb) blocks scripts and sub-resources,
        // but a CSP can't stop top-level navigation (meta refresh, link clicks), which would load a live page — with
        // scripts — straight from the WebView, outside the configured proxy / override IP / NIC. So only the document we
        // hand to NavigateToString may load: _renderPending is armed per render and cleared once it completes; the base URI
        // may be "navigated" at most once per render (WKWebView reports loadHTMLString's base URL as a navigation).
        private bool _renderPending;
        private Uri? _renderBase;
        private bool _renderBaseUnused;

        // A system without a usable web engine (no WebKitGTK on Linux, no WebView2 runtime, …) left the tab blank: the
        // control's own start-up failure ends in an async void the app's dispatcher handler swallows, and its "not
        // supported" text is drawn in the theme's light foreground on the white card. So the tab checks for the engine
        // itself and shows WebNotice in the page's place when none comes up.
        private const string GtkMissing = "Web preview needs WebKitGTK (libwebkit2gtk-4.1) on Linux.";
        private DispatcherTimer? _adapterWatch;

        // Defence in depth behind the CSP: WebView2 (Windows) runs with Blink's scriptEnabled switched off for the whole
        // engine. WKWebView / WebKitGTK / Android WebView expose no such switch; there the injected CSP alone blocks scripts.
        private const string NoScriptArg = "--blink-settings=scriptEnabled=false";

        public CurlView()
        {
            InitializeComponent();
            // AdapterCreated fires when the native engine is actually initialized — NavigateToString before this silently
            // no-ops. Re-render whenever the adapter (re)appears (it's torn down / rebuilt as the tab is hidden / shown).
            Web.AdapterCreated += (_, _) => { _adapterReady = true; _adapterWatch?.Stop(); ShowWebNotice(null); RenderWeb(); };
            Web.AdapterDestroyed += (_, _) => _adapterReady = false;
            Web.NavigationStarted += OnWebNavigationStarted;
            Web.NavigationCompleted += (_, _) => _renderPending = false;
            Web.NewWindowRequested += (_, e) => e.Handled = true;   // no pop-ups / target=_blank windows
            Web.EnvironmentRequested += OnWebEnvironmentRequested;
            Web.AttachedToVisualTree += (_, _) => WatchWebEngine();   // attached only while the tab is shown
            Web.DetachedFromVisualTree += (_, _) => _adapterWatch?.Stop();
            Web.PropertyChanged += (_, e) => { if (e.Property == NativeWebView.AdapterInfoProperty) CheckAdapterInfo(); };

            // The URL box imports a pasted curl command whole (a plain paste would keep only its first line, and the shared
            // URL cleaner would keep only the URL). Handled on the inner TextBox, before anything else sees it.
            UrlBox.AddHandler(TextBox.PastingFromClipboardEvent, OnUrlPasting, RoutingStrategies.Bubble);
            SearchInput.KeyDown += OnSearchKeyDown;
            KeyDown += OnViewKeyDown;
            InstallRenameFocus();
        }
        // NIC list refresh is driven by MainView's tab SelectionChanged (deterministic).

        protected override void OnDataContextChanged(EventArgs e)
        {
            base.OnDataContextChanged(e);
            if (_vm != null)
            {
                _vm.RenderWebRequested -= OnRenderWebRequested;
                _vm.PropertyChanged -= OnVmPropertyChanged;
            }
            _vm = DataContext as CurlViewModel;
            if (_vm != null)
            {
                _vm.RenderWebRequested += OnRenderWebRequested;
                _vm.PropertyChanged += OnVmPropertyChanged;
            }
        }

        // Tab / switch labels whose width changes in place (a count appears, "Saved" becomes "Saved (3)").
        private static readonly HashSet<string> StripLabels = new()
        {
            nameof(CurlViewModel.ParamsBadge), nameof(CurlViewModel.HeadersBadge), nameof(CurlViewModel.CookiesBadge),
            nameof(CurlViewModel.BodyBadge), nameof(CurlViewModel.AuthBadge), nameof(CurlViewModel.ResponseHeadersBadge),
            nameof(CurlViewModel.CookiesCountText), nameof(CurlViewModel.SavedTabText), nameof(CurlViewModel.HistoryTabText),
        };
        private bool _relayoutPending;

        private void OnVmPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            // the Save panel opens with its name selected, ready to type over
            if (e.PropertyName == nameof(CurlViewModel.IsSaveOpen) && _vm?.IsSaveOpen == true)
                Dispatcher.UIThread.Post(() => { SaveNameBox.Focus(); SaveNameBox.SelectAll(); }, DispatcherPriority.Input);
            if (e.PropertyName != null && StripLabels.Contains(e.PropertyName)) ScheduleStripRelayout();
        }

        // A tab header that grows in place (its count badge appears) is re-measured, but its strip's panel isn't always
        // re-arranged, which leaves the header at its old width with the badge cut off. Re-arrange the strips once.
        private void ScheduleStripRelayout()
        {
            if (_relayoutPending) return;
            _relayoutPending = true;
            Dispatcher.UIThread.Post(() =>
            {
                _relayoutPending = false;
                foreach (var ic in this.GetVisualDescendants().OfType<ItemsControl>())
                {
                    if (ic is not (TabControl or ListBox)) continue;
                    ic.ItemsPanelRoot?.InvalidateMeasure();
                    ic.ItemsPanelRoot?.InvalidateArrange();
                }
            }, DispatcherPriority.Background);
        }

        // ================================================================== URL box: paste / import

        private async void OnUrlPasting(object? sender, RoutedEventArgs e)
        {
            if (_vm is null || e.Source is not TextBox tb || tb.IsReadOnly) return;
            e.Handled = true;   // the cleaned value (or the import) replaces the raw paste
            try
            {
                string? raw = await ReadClipboardAsync();
                if (!string.IsNullOrEmpty(raw)) PasteIntoUrl(tb, raw, fromButton: false);
            }
            catch (Exception ex) { CrashLog.Write("Curl.Paste", ex); }   // never escape an async void handler
        }

        private async void OnUrlPasteClick(object? sender, RoutedEventArgs e)
        {
            if (_vm is null || InnerTextBox(UrlBox) is not { } tb) return;
            try
            {
                string? raw = await ReadClipboardAsync();
                if (string.IsNullOrEmpty(raw)) return;
                tb.Focus();
                PasteIntoUrl(tb, raw, fromButton: true);
            }
            catch (Exception ex) { CrashLog.Write("Curl.PasteButton", ex); }
        }

        private void PasteIntoUrl(TextBox tb, string raw, bool fromButton)
        {
            string? insert = _vm!.HandleUrlPaste(raw, out string? hint);
            Dispatcher.UIThread.Post(() => UrlBox.IsDropDownOpen = false, DispatcherPriority.Input);
            if (insert is null) return;   // imported as a whole request

            // One value: the button, an empty / fully selected box, the "https://" starter or a cleaned paste replace it all;
            // a clean fragment pasted into a partial selection behaves like a normal paste.
            string current = tb.Text ?? string.Empty;
            int s = Math.Clamp(Math.Min(tb.SelectionStart, tb.SelectionEnd), 0, current.Length);
            int end = Math.Clamp(Math.Max(tb.SelectionStart, tb.SelectionEnd), 0, current.Length);
            bool whole = fromButton || current.Length == 0 || (s == 0 && end == current.Length) || hint != null
                         || current.Trim() is "https://" or "http://";
            if (whole) { s = 0; end = current.Length; }
            tb.SelectionStart = s;
            tb.SelectionEnd = end;
            tb.SelectedText = insert.Replace("\r", " ").Replace("\n", " ");
        }

        private async Task<string?> ReadClipboardAsync()
        {
            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard is null) return null;
            try { return await clipboard.TryGetTextAsync(); }
            catch { return null; }   // clipboard held by another process
        }

        private static TextBox? InnerTextBox(Control host)
            => host as TextBox ?? host.GetVisualDescendants().OfType<TextBox>().FirstOrDefault();

        private void OnChipClick(object? sender, RoutedEventArgs e) => _vm?.OpenOptionsCommand.Execute(null);

        // ================================================================== files

        private async Task<(string Path, IStorageFile File)?> PickFileAsync(string title)
        {
            var top = TopLevel.GetTopLevel(this);
            if (top is null) return null;
            var files = await top.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = title,
                AllowMultiple = false,
                FileTypeFilter = new[] { FilePickerFileTypes.All },
            });
            if (files is not { Count: > 0 }) return null;
            var file = files[0];
            // desktop: the real path (curl reads it too); Android: the content URI, opened through the provider
            string path = file.TryGetLocalPath() ?? file.Path.ToString();
            return (path, file);
        }

        private async void OnChooseBodyFile(object? sender, RoutedEventArgs e)
        {
            if (_vm is null) return;
            try
            {
                if (await PickFileAsync("Choose the file to send as the body") is not { } picked) return;
                _vm.RegisterPickedFile(picked.Path, picked.File);
                _vm.BodyFilePath = picked.Path;
            }
            catch (Exception ex) { CrashLog.Write("Curl.ChooseBodyFile", ex); }
        }

        private async void OnChoosePartFile(object? sender, RoutedEventArgs e)
        {
            if (_vm is null || (sender as Control)?.DataContext is not CurlPartRow row) return;
            try
            {
                if (await PickFileAsync($"Choose a file for {(row.Name.Length > 0 ? row.Name : "the field")}") is not { } picked) return;
                _vm.RegisterPickedFile(picked.Path, picked.File);
                row.FilePath = picked.Path;
                row.IsFile = true;
                if (row.Name.Length == 0) row.Name = "file";
            }
            catch (Exception ex) { CrashLog.Write("Curl.ChoosePartFile", ex); }
        }

        private async void OnSaveBody(object? sender, RoutedEventArgs e)
        {
            if (_vm is null) return;
            try
            {
                var top = TopLevel.GetTopLevel(this);
                if (top is null) return;
                var file = await top.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
                {
                    Title = "Save the response body",
                    SuggestedFileName = _vm.SuggestedBodyFileName,
                    ShowOverwritePrompt = true,
                });
                if (file is null) return;
                string? error;
                await using (var stream = await file.OpenWriteAsync())
                    error = await _vm.SaveBodyAsync(stream);
                _vm.ReportSaved(file.Name, error);
            }
            catch (Exception ex) { _vm.ReportSaved(null, ex.Message); }
        }

        // ================================================================== search / keys

        private void OnFindNext(object? sender, RoutedEventArgs e) => BodyView.FindNext();
        private void OnFindPrev(object? sender, RoutedEventArgs e) => BodyView.FindNext(backwards: true);

        private void OnSearchKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) { BodyView.FindNext((e.KeyModifiers & KeyModifiers.Shift) != 0); e.Handled = true; }
            else if (e.Key == Key.Escape && _vm != null) { _vm.SearchText = string.Empty; e.Handled = true; }
        }

        private void OnViewKeyDown(object? sender, KeyEventArgs e)
        {
            bool cmd = (e.KeyModifiers & (KeyModifiers.Control | KeyModifiers.Meta)) != 0;
            if (cmd && e.Key == Key.F && _vm is { HasBodyText: true })
            {
                _vm.SectionIndex = 1;
                _vm.ResponseTabIndex = 0;
                Dispatcher.UIThread.Post(() => { SearchInput.Focus(); SearchInput.SelectAll(); }, DispatcherPriority.Input);
                e.Handled = true;
            }
        }

        private void OnRenameKeyDown(object? sender, KeyEventArgs e)
        {
            if (_vm is null || (sender as Control)?.DataContext is not CurlSavedItem item) return;
            if (e.Key == Key.Enter) { _vm.CommitRenameCommand.Execute(item); e.Handled = true; }
            else if (e.Key == Key.Escape) { _vm.CancelRenameCommand.Execute(item); e.Handled = true; }
        }

        // leaving the box keeps what was typed (Esc above discards it)
        private void OnRenameLostFocus(object? sender, RoutedEventArgs e)
        {
            if (_vm != null && (sender as Control)?.DataContext is CurlSavedItem { IsEditing: true } item)
                _vm.CommitRenameCommand.Execute(item);
        }

        // the rename box takes focus (all selected) when it appears
        private static bool _renameHookInstalled;
        private static void InstallRenameFocus()
        {
            if (_renameHookInstalled) return;
            _renameHookInstalled = true;
            IsVisibleProperty.Changed.AddClassHandler<TextBox>((tb, _) =>
            {
                if (tb.IsVisible && tb.Classes.Contains("renameBox"))
                    Dispatcher.UIThread.Post(() => { tb.Focus(); tb.SelectAll(); }, DispatcherPriority.Input);
            });
        }

        // ================================================================== preview (web)

        // A new response arrived: render it if the engine is ready; otherwise AdapterCreated will.
        private void OnRenderWebRequested() => Dispatcher.UIThread.Post(RenderWeb, DispatcherPriority.Background);

        private void RenderWeb()
        {
            if (_vm is null || Web is null || !_adapterReady) return;
            try
            {
                // the exact bytes the request returned (not a fresh navigation); for a direct request the base URI lets the
                // document's relative styles/images resolve against the URL
                _renderBase = _vm.WebBaseUri;
                _renderBaseUnused = _renderBase != null;
                _renderPending = true;
                Web.NavigateToString(_vm.WebHtml ?? string.Empty, _vm.WebBaseUri ?? new Uri("about:blank"));
            }
            catch
            {
                _renderPending = false;   // platform WebView unavailable / transient hiccup — re-renders next run
            }
        }

        private static void OnWebEnvironmentRequested(object? sender, WebViewEnvironmentRequestedEventArgs e)
        {
            if (e is WindowsWebView2EnvironmentRequestedEventArgs w2)
                w2.AdditionalBrowserArguments = string.IsNullOrWhiteSpace(w2.AdditionalBrowserArguments)
                    ? NoScriptArg : w2.AdditionalBrowserArguments + " " + NoScriptArg;
        }

        // The tab was opened. A missing Linux engine is known at once; anything else that keeps the engine from starting
        // shows up as no AdapterCreated within a grace period (WebView2's first start takes seconds).
        private void WatchWebEngine()
        {
            if (_adapterReady) return;
            if (OperatingSystem.IsLinux() && !LinuxWebEngineInstalled())
            {
                ShowWebNotice(GtkMissing);
                // out of the tree for good, so the control doesn't retry (and fail) on every visit — posted: this runs inside
                // the attach pass, which mustn't see the panel's children change under it
                Dispatcher.UIThread.Post(() => WebHost.Children.Remove(Web));
                return;
            }
            CheckAdapterInfo();
            if (_adapterWatch is null)
            {
                _adapterWatch = new DispatcherTimer { Interval = TimeSpan.FromSeconds(10) };
                _adapterWatch.Tick += (_, _) =>
                {
                    _adapterWatch.Stop();
                    if (!_adapterReady && !WebNotice.IsVisible)
                        ShowWebNotice("Web preview unavailable: the system web engine didn't start.");
                };
            }
            _adapterWatch.Stop();   // restart the grace period
            _adapterWatch.Start();
        }

        // The control's own probes (dlopen + version getters, no GTK init) — cheap and safe on the UI thread.
        private static bool LinuxWebEngineInstalled()
        {
            try
            {
                return WebViewAdapterInfo.GetAdapterInfo(WebViewAdapterType.WebKitGtk) is { IsInstalled: true }
                    || WebViewAdapterInfo.GetAdapterInfo(WebViewAdapterType.WpeWebKit) is { IsInstalled: true };
            }
            catch { return true; }   // can't tell: let the control try — the grace-period watch still reports it
        }

        // NativeWebView sets AdapterInfo once its engine factory resolves; "not supported" / "not installed" there means no
        // engine is coming.
        private void CheckAdapterInfo()
        {
            if (_adapterReady || Web.AdapterInfo is not DetailedWebViewAdapterInfo info || (info.IsSupported && info.IsInstalled)) return;
            ShowWebNotice(OperatingSystem.IsLinux() ? GtkMissing
                : "Web preview unavailable: " + (string.IsNullOrWhiteSpace(info.UnavailableReason) ? "no web engine on this system." : info.UnavailableReason));
        }

        private void ShowWebNotice(string? text)
        {
            if (text != null) WebNoticeText.Text = text;
            WebNotice.IsVisible = text != null;
        }

        private void OnWebNavigationStarted(object? sender, WebViewNavigationStartingEventArgs e)
        {
            try
            {
                var u = e.Request;
                if (u is null) return;
                if (!u.IsAbsoluteUri) { if (!_renderPending) e.Cancel = true; return; }
                if (u.Scheme == "about") return;                                    // about:blank etc. — inert
                if (_renderPending)
                {
                    if (u.Scheme == "data") return;                                 // NavigateToString's own load
                    if (_renderBaseUnused && _renderBase != null && u == _renderBase) { _renderBaseUnused = false; return; }
                }
                e.Cancel = true;   // anything the page itself tries (refresh, link, form, location=…)
            }
            catch
            {
                e.Cancel = true;
            }
        }
    }
}
