using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using PCAPAnalyzer.UI.Views.Base;

namespace PCAPAnalyzer.UI.Views;

public partial class PacketNumbersDetailWindow : BaseDetailWindow
{
    public PacketNumbersDetailWindow()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private void CloseButton_Click(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}