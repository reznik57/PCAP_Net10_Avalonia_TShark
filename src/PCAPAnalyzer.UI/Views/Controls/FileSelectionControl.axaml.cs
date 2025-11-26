using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using PCAPAnalyzer.UI.ViewModels;
using System;
using System.Linq;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views.Controls;

public partial class FileSelectionControl : UserControl
{
    private Border? _dropZoneBorder;

    public FileSelectionControl()
    {
        InitializeComponent();
        AddHandler(DragDrop.DropEvent, OnDrop);
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DragEnterEvent, OnDragEnter);
        AddHandler(DragDrop.DragLeaveEvent, OnDragLeave);
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
        _dropZoneBorder = this.FindControl<Border>("DropZoneBorder");
    }

    /// <summary>
    /// Handle drag enter - add visual feedback (blue glow, solid border)
    /// </summary>
    private void OnDragEnter(object? sender, DragEventArgs e)
    {
        var files = e.DataTransfer.TryGetFiles();
        if (files != null && files.Any())
        {
            // Add DragOver class for blue glow effect
            if (_dropZoneBorder != null && !_dropZoneBorder.Classes.Contains("DragOver"))
            {
                _dropZoneBorder.Classes.Add("DragOver");
            }
        }
    }

    /// <summary>
    /// Handle drag leave - remove visual feedback
    /// </summary>
    private void OnDragLeave(object? sender, DragEventArgs e)
    {
        // Remove DragOver class
        if (_dropZoneBorder != null && _dropZoneBorder.Classes.Contains("DragOver"))
        {
            _dropZoneBorder.Classes.Remove("DragOver");
        }
    }

    /// <summary>
    /// Handle drag over for visual feedback
    /// </summary>
    private void OnDragOver(object? sender, DragEventArgs e)
    {
        // Only allow file drops
        var files = e.DataTransfer.TryGetFiles();
        if (files != null && files.Any())
        {
            e.DragEffects = DragDropEffects.Copy;
        }
        else
        {
            e.DragEffects = DragDropEffects.None;
        }

        e.Handled = true;
    }

    /// <summary>
    /// Handle file drop
    /// </summary>
    private void OnDrop(object? sender, DragEventArgs e)
    {
        // Remove drag-over visual state
        if (_dropZoneBorder != null && _dropZoneBorder.Classes.Contains("DragOver"))
        {
            _dropZoneBorder.Classes.Remove("DragOver");
        }

        var files = e.DataTransfer.TryGetFiles()?.ToArray();
        if (files == null || files.Length == 0)
            return;

        var filePath = files[0].Path.LocalPath;

        // Validate PCAP file extension
        var ext = System.IO.Path.GetExtension(filePath).ToLowerInvariant();
        if (ext != ".pcap" && ext != ".pcapng" && ext != ".cap")
        {
            DebugLogger.Log($"[FileSelectionControl] Invalid file type: {ext}. Only .pcap, .pcapng, .cap are supported.");
            return;
        }

        // Get FileAnalysisViewModel from DataContext chain
        if (DataContext is ViewModels.Components.FileSelectionControlViewModel vm)
        {
            var fileAnalysisVm = GetFileAnalysisViewModel(vm);
            if (fileAnalysisVm != null)
            {
                DebugLogger.Log($"[FileSelectionControl] File dropped: {filePath}");
                fileAnalysisVm.SelectedFilePath = filePath;

                // Optionally auto-start analysis after drop
                if (fileAnalysisVm.AnalyzeCommand?.CanExecute(null) == true)
                {
                    DebugLogger.Log($"[FileSelectionControl] Auto-starting analysis...");
                    _ = ((CommunityToolkit.Mvvm.Input.IAsyncRelayCommand)fileAnalysisVm.AnalyzeCommand).ExecuteAsync(null);
                }
            }
        }

        e.Handled = true;
    }

    /// <summary>
    /// Get FileAnalysisViewModel from FileSelectionControlViewModel
    /// </summary>
    private FileAnalysisViewModel? GetFileAnalysisViewModel(ViewModels.Components.FileSelectionControlViewModel vm)
    {
        // Access private field via reflection
        var field = vm.GetType().GetField("_fileAnalysisViewModel",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        return field?.GetValue(vm) as FileAnalysisViewModel;
    }

    /// <summary>
    /// Handle tap on collapsed bar to expand
    /// </summary>
    private void OnCollapsedBarTapped(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (DataContext is ViewModels.Components.FileSelectionControlViewModel vm)
        {
            if (vm.ExpandCommand?.CanExecute(null) == true)
            {
                vm.ExpandCommand.Execute(null);
            }
        }
    }

    /// <summary>
    /// Handle click/tap on drop zone to browse for file
    /// </summary>
    private void OnDropZoneTapped(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        // Don't trigger if the Browse button was clicked (it will handle itself)
        if (e.Source is Button)
            return;

        if (DataContext is ViewModels.Components.FileSelectionControlViewModel vm)
        {
            if (vm.BrowseCommand?.CanExecute(null) == true)
            {
                DebugLogger.Log("[FileSelectionControl] Drop zone clicked - triggering Browse");
                vm.BrowseCommand.Execute(null);
            }
        }
    }
}
