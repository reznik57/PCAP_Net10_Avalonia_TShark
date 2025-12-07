using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using PCAPAnalyzer.UI.ViewModels;

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

    /// <summary>
    /// Handle drag over to show drop cursor for valid PCAP files.
    /// </summary>
    public void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = DragDropEffects.None;

        // Get files from drag data (suppress obsolete warning - DataTransfer.GetFiles() not available)
        #pragma warning disable CS0618
        if (e.Data.Contains(DataFormats.Files))
        {
            var files = e.Data.GetFiles()?.ToList();
            if (files is not null && files.Count == 1)
            {
                var filePath = files[0].Path.LocalPath;
                if (FileManagerViewModel.IsValidPcapFile(filePath))
                {
                    e.DragEffects = DragDropEffects.Copy;
                }
            }
        }
        #pragma warning restore CS0618

        e.Handled = true;
    }

    /// <summary>
    /// Handle file drop - accept only valid PCAP files.
    /// </summary>
    public void OnDrop(object? sender, DragEventArgs e)
    {
        // Get files from drag data (suppress obsolete warning - DataTransfer.GetFiles() not available)
        #pragma warning disable CS0618
        if (e.Data.Contains(DataFormats.Files))
        {
            var files = e.Data.GetFiles()?.ToList();
            if (files is not null && files.Count == 1)
            {
                var filePath = files[0].Path.LocalPath;

                if (DataContext is FileManagerViewModel viewModel)
                {
                    viewModel.SelectFile(filePath);
                }
            }
        }
        #pragma warning restore CS0618

        e.Handled = true;
    }
}
