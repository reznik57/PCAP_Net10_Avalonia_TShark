using Avalonia.Markup.Xaml;
using PCAPAnalyzer.UI.Views.Base;

namespace PCAPAnalyzer.UI.Views
{
    public partial class EnhancedPacketDetailWindow : BaseDetailWindow
    {
        public EnhancedPacketDetailWindow()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
    }
}