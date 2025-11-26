using System;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace PCAPAnalyzer.UI.Controls.Charts
{
    public partial class InteractiveTimeSeriesChart : UserControl
    {
        public InteractiveTimeSeriesChart()
        {
            InitializeComponent();
        }

        private void ResetZoom_Click(object? sender, RoutedEventArgs e)
        {
            // Reset zoom logic
            if (DataContext is IInteractiveChartViewModel vm)
            {
                vm.ResetZoom();
            }
        }

        private void TogglePan_Click(object? sender, RoutedEventArgs e)
        {
            // Toggle pan mode
            if (DataContext is IInteractiveChartViewModel vm)
            {
                vm.TogglePanMode();
            }
        }
    }

    public interface IInteractiveChartViewModel
    {
        void ResetZoom();
        void TogglePanMode();
    }
}
