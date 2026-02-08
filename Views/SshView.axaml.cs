using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using System;

namespace Echoes.Views;

public partial class SshView : UserControl
{
    public SshView()
    {
        InitializeComponent();

        var outputBlock = this.FindControl<SelectableTextBlock>("TerminalOutputBlock");
        var scrollViewer = this.FindControl<ScrollViewer>("TermScroll");

        if (outputBlock != null && scrollViewer != null)
        {
            outputBlock.PropertyChanged += (s, e) =>
            {
                if (e.Property == SelectableTextBlock.TextProperty)
                {
                    Dispatcher.UIThread.Post(() =>
                    {
                        scrollViewer.Offset = new Vector(scrollViewer.Offset.X, double.MaxValue);
                    }, DispatcherPriority.Background);
                }
            };
        }
    }
}