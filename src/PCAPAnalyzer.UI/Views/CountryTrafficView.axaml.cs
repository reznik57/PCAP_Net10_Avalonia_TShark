using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Constants;
using Microsoft.Extensions.DependencyInjection;
using System;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views
{
    public partial class CountryTrafficView : UserControl
    {
        private CountryTrafficViewModel? _viewModel;

        public CountryTrafficView()
        {
            InitializeComponent();
            DataContextChanged += OnDataContextChanged;
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        private void OnDataContextChanged(object? sender, EventArgs e)
        {
            _viewModel = DataContext as CountryTrafficViewModel;
            WireUpFilterPanelEvents();
        }

        private void WireUpFilterPanelEvents()
        {
            var filterPanel = this.FindControl<Controls.UnifiedFilterPanelControl>("UnifiedFilterPanel");
            if (filterPanel?.DataContext is UnifiedFilterPanelViewModel filterPanelVm)
            {
                filterPanelVm.ApplyFiltersRequested += OnFilterPanelApplyRequested;
                DebugLogger.Log("[CountryTrafficView] Wired ApplyFiltersRequested event");
            }
        }

        private void OnFilterPanelApplyRequested()
        {
            // Country Traffic view updates are already handled by GlobalFilterState.OnFilterChanged
            // subscription in CountryTrafficViewModel, which triggers UpdateTopCountriesList()
            // This event handler is here for consistency and potential future enhancements
            DebugLogger.Log("[CountryTrafficView] ApplyFiltersRequested - filter update triggered");
        }

        /// <summary>
        /// Handles clicking the dark overlay background to close the drill-down popup
        /// </summary>
        private void OnPopupBackgroundPressed(object? sender, PointerPressedEventArgs e)
        {
            if (DataContext is CountryTrafficViewModel viewModel)
            {
                viewModel.DrillDown.IsVisible = false;
            }
        }

        /// <summary>
        /// Handles filter copy button click - copies CommonFilters to selected destination tab
        /// </summary>
        private void OnFilterCopyClick(object? sender, RoutedEventArgs e)
        {
            try
            {
                var filterCopyService = App.Services?.GetService<FilterCopyService>();
                if (filterCopyService == null)
                {
                    DebugLogger.Log("[CountryTrafficView] FilterCopyService not available");
                    return;
                }

                var comboBox = this.FindControl<ComboBox>("FilterCopyDestination");
                if (comboBox?.SelectedItem is ComboBoxItem selectedItem)
                {
                    var destinationTabName = selectedItem.Content?.ToString();
                    if (string.IsNullOrEmpty(destinationTabName))
                    {
                        DebugLogger.Log("[CountryTrafficView] No destination tab selected");
                        return;
                    }

                    var success = filterCopyService.CopyFilters(TabNames.CountryTraffic, destinationTabName);

                    if (success)
                    {
                        DebugLogger.Log($"[CountryTrafficView] Successfully copied filters to {destinationTabName}");
                    }
                    else
                    {
                        DebugLogger.Log($"[CountryTrafficView] Failed to copy filters to {destinationTabName}");
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[CountryTrafficView] OnFilterCopyClick error: {ex.Message}");
            }
        }
    }
}