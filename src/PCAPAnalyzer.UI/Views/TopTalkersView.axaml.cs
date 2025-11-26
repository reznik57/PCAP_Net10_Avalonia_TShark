using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Views;

public partial class TopTalkersView : UserControl
{
    public TopTalkersView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
