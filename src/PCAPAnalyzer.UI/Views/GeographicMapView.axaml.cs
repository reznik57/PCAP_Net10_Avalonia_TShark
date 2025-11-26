using Avalonia.Controls;
using Avalonia.Input;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views
{
    public partial class GeographicMapView : UserControl
    {
        public GeographicMapView()
        {
            InitializeComponent();
            
            // Enable keyboard shortcuts
            KeyDown += OnKeyDown;
        }
        
        private void OnKeyDown(object? sender, KeyEventArgs e)
        {
            if (DataContext is not CountryTrafficViewModel vm) return;
            
            switch (e.Key)
            {
                case Key.Add:
                case Key.OemPlus:
                    vm.ZoomInCommand.Execute(null);
                    break;
                case Key.Subtract:
                case Key.OemMinus:
                    vm.ZoomOutCommand.Execute(null);
                    break;
                case Key.R:
                    if (e.KeyModifiers == KeyModifiers.Control)
                        vm.ResetViewCommand.Execute(null);
                    break;
                case Key.A:
                    if (e.KeyModifiers == KeyModifiers.Control)
                        vm.ShowAnimations = !vm.ShowAnimations;
                    break;
                case Key.F:
                    if (e.KeyModifiers == KeyModifiers.Control)
                        vm.ShowTrafficFlows = !vm.ShowTrafficFlows;
                    break;
                case Key.L:
                    if (e.KeyModifiers == KeyModifiers.Control)
                        vm.ShowCountryLabels = !vm.ShowCountryLabels;
                    break;
            }
        }
    }
}