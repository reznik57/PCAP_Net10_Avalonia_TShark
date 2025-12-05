using Avalonia.Markup.Xaml;
using PCAPAnalyzer.UI.Views.Base;

namespace PCAPAnalyzer.UI.Views
{
    public partial class PacketDetailPopupWindow : BaseDetailWindow
    {
        public PacketDetailPopupWindow()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
    }
}