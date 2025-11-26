using Avalonia.Controls;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views
{
    /// <summary>
    /// Report view that displays network analysis reports.
    /// Uses dependency injection to obtain the ReportViewModel.
    /// </summary>
    public partial class ReportView : UserControl
    {
        public ReportView()
        {
            InitializeComponent();

            // Obtain ViewModel from DI container
            // The DataContext will be set by the parent window/view or via DI
            if (Design.IsDesignMode)
            {
                // Design-time: Create a dummy instance for XAML preview
                DataContext = null; // Designer will handle this
            }
            else
            {
                // Runtime: Get ViewModel from DI container
                DataContext = App.Services.GetRequiredService<ReportViewModel>();
            }
        }
    }
}