using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Controls
{
    public partial class PopupTableView : UserControl
    {
        public PopupTableView()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
    }
}