using Avalonia.Controls;
using System.Collections.Specialized;

namespace Echoes.Views;

public partial class MonitorView : UserControl
{
    public MonitorView()
    {
        InitializeComponent();
        //var list = this.FindControl<ListBox>("MonitorList");
        //if (list != null)
        //{
        //    ((INotifyCollectionChanged)list.Items).CollectionChanged += (s, e) =>
        //    {
        //        if (e.Action == NotifyCollectionChangedAction.Add) list.ScrollIntoView(list.Items.Count - 1);
        //    };
        //}
    }
}