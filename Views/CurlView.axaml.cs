using Avalonia.Controls;
using Avalonia.Threading;
using Echoes.ViewModels;
using System;
using System.ComponentModel;
namespace Echoes.Views
{
    public partial class CurlView : UserControl
    {
        public CurlView()
        {
            InitializeComponent();
        }
        // NIC list refresh is driven by MainView's tab SelectionChanged (deterministic).

        //private void Vm_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        //{
        //    if (e.PropertyName == nameof(CurlViewModel.RawBody))
        //    {
        //        if (DataContext is CurlViewModel vm)
        //        {
        //            FullLog.Text = vm.RawBody;
        //        }
        //    }
        //}
    }
}