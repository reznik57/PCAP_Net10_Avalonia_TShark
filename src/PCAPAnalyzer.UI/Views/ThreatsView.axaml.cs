using System.ComponentModel;
using Avalonia.Controls;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views
{
    /// <summary>
    /// ThreatsView - Main view for security threats analysis
    /// Chart hover handlers are in ThreatsView.ChartHandlers.cs partial class
    /// </summary>
    public partial class ThreatsView : UserControl
    {
        private ThreatsViewModel? _viewModel;

        public ThreatsView()
        {
            InitializeComponent();

            // ✅ FIX: Don't override DataContext - accept it from parent XAML binding
            // DataContext is set via: <ThreatsView DataContext="{Binding ThreatsViewModel}" /> in MainWindow.axaml
            // Creating a separate instance here caused duplicate ViewModels (memory waste + wrong data)
            DataContextChanged += (s, e) =>
            {
                if (_viewModel != null)
                    _viewModel.PropertyChanged -= OnViewModelPropertyChanged;

                _viewModel = DataContext as ThreatsViewModel;
                if (_viewModel != null)
                    _viewModel.PropertyChanged += OnViewModelPropertyChanged;
            };
        }

        private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            // Clean up highlight series when chart data is refreshed
            if (e.PropertyName == nameof(ThreatsViewModel.ThreatTimelineSeries))
            {
                CleanupHighlightSeries();
            }
        }

    }
}
