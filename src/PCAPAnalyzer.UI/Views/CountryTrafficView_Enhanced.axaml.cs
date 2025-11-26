using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.VisualTree;
using PCAPAnalyzer.UI.Controls;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Constants;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views
{
    public partial class CountryTrafficView_Enhanced : UserControl
    {
        public CountryTrafficView_Enhanced()
        {
            InitializeComponent();
            SetupContinentClickHandlers();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
        
        private void SetupContinentClickHandlers()
        {
            // Find the world map control and set up click handler
            this.Loaded += (sender, e) =>
            {
                // Set up handlers for all continent map controls
                var worldMapControl = this.FindControl<ContinentMapControlV2>("WorldMapControl");
                if (worldMapControl != null)
                {
                    worldMapControl.ContinentClicked = OnContinentClicked;
                }

                // Also set up handlers for continent-specific maps
                var allMapControls = this.GetVisualDescendants().OfType<ContinentMapControlV2>();
                foreach (var mapControl in allMapControls)
                {
                    mapControl.ContinentClicked = OnContinentClicked;
                }
            };
        }

        private void OnContinentClicked(string continentCode)
        {
            DebugLogger.Log($"[CountryTrafficView_Enhanced] Continent clicked: {continentCode}");

            // Get the view model and call the navigation method
            if (DataContext is CountryTrafficViewModel viewModel)
            {
                viewModel.OnContinentClicked(continentCode);
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