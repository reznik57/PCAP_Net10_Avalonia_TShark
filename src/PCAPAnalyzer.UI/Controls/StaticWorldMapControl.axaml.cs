using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Controls
{
    public partial class StaticWorldMapControl : UserControl
    {
        public static readonly StyledProperty<string?> SelectedContinentProperty =
            AvaloniaProperty.Register<StaticWorldMapControl, string?>(nameof(SelectedContinent));

        public string? SelectedContinent
        {
            get => GetValue(SelectedContinentProperty);
            set => SetValue(SelectedContinentProperty, value);
        }

        public event EventHandler<ContinentSelectedEventArgs>? ContinentSelected;

        public StaticWorldMapControl()
        {
            InitializeComponent();
            AttachEventHandlers();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        private void AttachEventHandlers()
        {
            var northAmerica = this.FindControl<Avalonia.Controls.Shapes.Path>("NorthAmerica");
            var southAmerica = this.FindControl<Avalonia.Controls.Shapes.Path>("SouthAmerica");
            var europe = this.FindControl<Avalonia.Controls.Shapes.Path>("Europe");
            var africa = this.FindControl<Avalonia.Controls.Shapes.Path>("Africa");
            var asia = this.FindControl<Avalonia.Controls.Shapes.Path>("Asia");
            var oceania = this.FindControl<Avalonia.Controls.Shapes.Path>("Oceania");

            if (northAmerica != null)
                northAmerica.PointerPressed += (s, e) => OnContinentClicked("NorthAmerica", e);
            
            if (southAmerica != null)
                southAmerica.PointerPressed += (s, e) => OnContinentClicked("SouthAmerica", e);
            
            if (europe != null)
                europe.PointerPressed += (s, e) => OnContinentClicked("Europe", e);
            
            if (africa != null)
                africa.PointerPressed += (s, e) => OnContinentClicked("Africa", e);
            
            if (asia != null)
                asia.PointerPressed += (s, e) => OnContinentClicked("Asia", e);
            
            if (oceania != null)
                oceania.PointerPressed += (s, e) => OnContinentClicked("Oceania", e);
        }

        private void OnContinentClicked(string continentName, PointerPressedEventArgs e)
        {
            SelectedContinent = continentName;
            ContinentSelected?.Invoke(this, new ContinentSelectedEventArgs(continentName));
            e.Handled = true;
        }
    }

    public class ContinentSelectedEventArgs : EventArgs
    {
        public string ContinentName { get; }

        public ContinentSelectedEventArgs(string continentName)
        {
            ContinentName = continentName;
        }
    }
}