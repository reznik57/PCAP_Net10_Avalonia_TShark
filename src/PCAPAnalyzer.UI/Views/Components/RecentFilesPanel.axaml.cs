using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views.Components;

public partial class RecentFilesPanel : UserControl
{
    public RecentFilesPanel()
    {
        InitializeComponent();
    }

    private void OnRecentFileClick(object? sender, PointerPressedEventArgs e)
    {
        if (sender is Grid grid && grid.DataContext is RecentFileInfo fileInfo)
        {
            if (DataContext is RecentFilesViewModel viewModel)
            {
                viewModel.SelectFileCommand.Execute(fileInfo);
            }
        }
    }

    private void OnCopyPathClick(object? sender, RoutedEventArgs e)
    {
        if (sender is MenuItem menuItem && menuItem.DataContext is RecentFileInfo fileInfo)
        {
            try
            {
                var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
                if (clipboard != null)
                {
                    _ = clipboard.SetTextAsync(fileInfo.FilePath);
                    DebugLogger.Log($"[RecentFilesPanel] Copied path to clipboard: {fileInfo.FilePath}");
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[RecentFilesPanel] Error copying to clipboard: {ex.Message}");
            }
        }
    }
}
