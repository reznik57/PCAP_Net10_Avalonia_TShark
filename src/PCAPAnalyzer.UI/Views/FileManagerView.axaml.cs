using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Views;

/// <summary>
/// File Manager view - dedicated tab for file selection, information, and quick statistics.
/// Provides a central location for file operations and analysis status.
/// </summary>
public partial class FileManagerView : UserControl
{
    public FileManagerView()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
