using Avalonia.Controls;
using Echoes.ViewModels;

namespace Echoes.Views;

public partial class StringLabView : UserControl
{
    public StringLabView()
    {
        InitializeComponent();
        DataContext = new StringLabViewModel();
    }
}