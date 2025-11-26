using System;
using System.ComponentModel;
using Avalonia.Controls;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.Core.Utilities;

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
            _viewModel = ResolveViewModel();
            DataContext = _viewModel;

            // Subscribe to property changes for chart cleanup
            if (_viewModel != null)
            {
                _viewModel.PropertyChanged += OnViewModelPropertyChanged;
            }
        }

        private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            // Clean up highlight series when chart data is refreshed
            if (e.PropertyName == nameof(ThreatsViewModel.ThreatTimelineSeries))
            {
                CleanupHighlightSeries();
            }
        }

        private static ThreatsViewModel ResolveViewModel()
        {
            try
            {
                return App.Services?.GetService<ThreatsViewModel>() ?? new ThreatsViewModel();
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedThreatsView] Failed to resolve ThreatsViewModel: {ex.Message}");
                return new ThreatsViewModel();
            }
        }
    }
}
