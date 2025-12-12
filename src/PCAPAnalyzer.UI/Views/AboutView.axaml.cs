using Avalonia.Controls;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views;

public partial class AboutView : UserControl
{
    public AboutView()
    {
        InitializeComponent();
    }

    protected override async void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        if (DataContext is AboutViewModel vm)
        {
            await vm.LoadDependenciesAsync();
        }
    }
}
