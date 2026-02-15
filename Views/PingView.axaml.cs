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
    }
}