using Avalonia.Controls;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Views.Controls;

public partial class UnifiedFilterPanelControl : UserControl
{
    public UnifiedFilterPanelControl()
    {
        InitializeComponent();

        if (!Design.IsDesignMode)
        {
            DataContext = App.Services.GetRequiredService<UnifiedFilterPanelViewModel>();
        }
    }
}
