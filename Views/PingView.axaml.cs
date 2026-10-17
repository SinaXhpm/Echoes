using Avalonia.Controls;
using System.Collections.Specialized;

namespace Echoes.Views;

public partial class PingView : UserControl
{
    public PingView()
    {
        InitializeComponent();

        var listBox = this.FindControl<ListBox>("LogList");
        if (listBox?.Items is INotifyCollectionChanged collection)
        {
            collection.CollectionChanged += (s, e) =>
            {
                if (e.Action == NotifyCollectionChangedAction.Add)
                {
                    listBox.ScrollIntoView(listBox.Items.Count - 1);
                }
            };
        }

        // Paste-to-host and select-all-on-focus for the host box are declared in XAML via
        // helpers:InputAssist (HostPaste / SelectAllOnFocus; in TCP mode PortTarget sends a pasted port to the Port box).
        // The placeholder comes from the view-model (PingViewModel.HostPlaceholder): shorter on a phone, where the
        // narrower box (Start beside it) cut the example off mid-address ("e.g. 8").
    }
}
