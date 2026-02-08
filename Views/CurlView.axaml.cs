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
            DataContextChanged += (s, e) =>
            {
                if (DataContext is CurlViewModel vm)
                {
                    vm.PropertyChanged += Vm_PropertyChanged;
                }
            };
        }

        private void Vm_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(CurlViewModel.RawBody))
            {
                if (DataContext is CurlViewModel vm)
                {
                    MyHtmlPanel.Text = vm.RawBody;
                }
            }
        }
    }
}