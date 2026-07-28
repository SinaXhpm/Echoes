using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Echoes.ViewModels;
using System;

namespace Echoes.Views
{
    public partial class CurlView : UserControl
    {
        private CurlViewModel? _vm;
        private bool _adapterReady;

        public CurlView()
        {
            InitializeComponent();
            // AdapterCreated fires when the native engine (WebView2 / WKWebView / Android WebView) is
            // actually initialized — NavigateToString before this silently no-ops, which is why the
            // page came up blank when we rendered on Loaded. Re-render whenever the adapter (re)appears
            // (the control's adapter is torn down / rebuilt as the WEB tab is hidden / shown).
            Web.AdapterCreated += (_, _) => { _adapterReady = true; RenderWeb(); };
            Web.AdapterDestroyed += (_, _) => _adapterReady = false;
        }
        // NIC list refresh is driven by MainView's tab SelectionChanged (deterministic).

        protected override void OnDataContextChanged(EventArgs e)
        {
            base.OnDataContextChanged(e);
            if (_vm != null) _vm.RenderWebRequested -= OnRenderWebRequested;
            _vm = DataContext as CurlViewModel;
            if (_vm != null) _vm.RenderWebRequested += OnRenderWebRequested;
        }

        // A new response arrived: render it if the engine is ready; otherwise AdapterCreated will.
        private void OnRenderWebRequested() => Dispatcher.UIThread.Post(RenderWeb, DispatcherPriority.Background);

        private void RenderWeb()
        {
            if (_vm is null || Web is null || !_adapterReady) return;
            try
            {
                // Show the exact bytes the request returned (not a fresh navigation to the URL); the
                // base URI lets the document's relative assets resolve against the original URL.
                Web.NavigateToString(_vm.WebHtml ?? string.Empty, _vm.WebBaseUri ?? new Uri("about:blank"));
            }
            catch
            {
                // Platform WebView unavailable / transient hiccup — never crash; re-renders next run.
            }
        }
    }
}
