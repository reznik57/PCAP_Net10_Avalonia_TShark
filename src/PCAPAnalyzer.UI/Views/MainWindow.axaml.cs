using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using SkiaSharp;
using PCAPAnalyzer.Core.Monitoring;
using PCAPAnalyzer.UI.Utilities;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.UI.Services;

using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views;

[SuppressMessage("Maintainability", "CA1506:Avoid excessive class coupling",
    Justification = "MainWindow is the central UI coordinator - high coupling is expected for main window handling tabs, drag-drop, screenshots, chart interactions, and keyboard shortcuts")]
public partial class MainWindow : Window
{
    public MainWindow()
        : this(ResolveViewModel())
    {
    }

    public MainWindow(MainWindowViewModel viewModel)
    {
        try
        {
            DebugLogger.Log("[MainWindow] Initializing components...");
            InitializeComponent();
            DebugLogger.Log("[MainWindow] Components initialized");

            DataContext = viewModel;
            DebugLogger.Log("[MainWindow] ViewModel provided and set as DataContext");

            // NOTE: Drag & drop is now handled by FileManagerView
            // Setup keyboard shortcut handlers (DEFERRED - API alignment needed)
            // SetupKeyboardShortcuts();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error in constructor: {ex.Message}");
            DebugLogger.Log($"[MainWindow] Stack trace: {ex.StackTrace}");

            if (ex.InnerException is not null)
            {
                DebugLogger.Log($"[MainWindow] Inner exception: {ex.InnerException.Message}");
                DebugLogger.Log($"[MainWindow] Inner stack trace: {ex.InnerException.StackTrace}");
            }

            throw;
        }
    }

    private static MainWindowViewModel ResolveViewModel()
    {
        try
        {
            return App.Services?.GetService<MainWindowViewModel>() ?? new MainWindowViewModel();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Failed to resolve ViewModel from service provider: {ex.Message}");
            return new MainWindowViewModel();
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        // Report integrity and health status on close
        DebugLogger.Log("\n[SHUTDOWN] Application closing...");
        IntegrityMonitor.Report();
        // ✅ PERFORMANCE FIX: Removed HealthMonitor.LogStatus() - monitor no longer used

        try
        {
            DebugLogger.Log("[MainWindow] Window closing...");
            base.OnClosed(e);
            (DataContext as MainWindowViewModel)?.Dispose();
            DebugLogger.Log("[MainWindow] Window closed and resources disposed");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error in OnClosed: {ex.Message}");
        }
    }
    
    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);

        // Find the TabControl and add selection changed handler
        var tabControl = this.FindControl<TabControl>("MainTabControl");
        if (tabControl is not null)
        {
            tabControl.SelectionChanged += OnTabSelectionChanged;
        }

        // Subscribe to Charts ViewModel property changes to reset highlight when series are rebuilt
        if (DataContext is MainWindowViewModel vm && vm.Charts is not null)
        {
            vm.Charts.PropertyChanged += OnChartsPropertyChanged;
        }
    }

    private void OnChartsPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Reset highlight references when the series collection is replaced
        if (e.PropertyName == nameof(ViewModels.Components.MainWindowChartsViewModel.PacketsOverTimeSeries))
        {
            ResetPacketsChartHighlight();
        }
    }
    
    /// <summary>
    /// Handles tab selection changes with animation.
    /// Uses fire-and-forget pattern with exception handling to avoid async void.
    /// </summary>
    private void OnTabSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (sender is TabControl tabControl && DataContext is MainWindowViewModel viewModel)
        {
            _ = HandleTabSelectionChangedAsync(tabControl, viewModel);
        }
    }

    private async Task HandleTabSelectionChangedAsync(TabControl tabControl, MainWindowViewModel viewModel)
    {
        try
        {
            var selectedTab = tabControl.SelectedItem as TabItem;

            // Animate the tab content with fade-in effect
            if (selectedTab?.Content is Control content)
            {
                await AnimateTabContentFadeIn(content);
            }

            // Continue with original logic
            selectedTab = tabControl.SelectedItem as TabItem;
            if (selectedTab is not null)
            {
                var header = selectedTab.Header?.ToString() ?? "";
                var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                DebugLogger.Log($"[{timestamp}] [TAB-SWITCH] User clicked tab: '{header}' - BEGIN");

                // If switching to Dashboard tab, ensure it's safe to display
                if (header.Contains("Dashboard", StringComparison.Ordinal))
                {
                    DebugLogger.Log("[MainWindow] Dashboard tab selected");

                    // Ensure dashboard is initialized
                    if (viewModel.DashboardViewModel is null)
                    {
                        DebugLogger.Log("[MainWindow] Dashboard not initialized, creating new instance");
                        try
                        {
                            viewModel.DashboardViewModel = new();
                        }
                        catch (Exception dashEx)
                        {
                            DebugLogger.Log($"[MainWindow] Failed to create DashboardViewModel: {dashEx.Message}");
                            return;
                        }
                    }

                    // Only update dashboard if we have completed analysis with data
                    // Skip the update if analysis is in progress to prevent crashes
                    if (viewModel.PacketCount > 0 && !viewModel.IsAnalyzing)
                    {
                        DebugLogger.Log($"[MainWindow] Dashboard update conditions met: PacketCount={viewModel.PacketCount}, IsAnalyzing={viewModel.IsAnalyzing}");

                        // Delay slightly to ensure UI is ready
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                // Add a small delay to let UI stabilize
                                await Task.Delay(100);

                                // Check again that we should update
                                if (viewModel.DashboardViewModel is not null && !viewModel.IsAnalyzing)
                                {
                                    DebugLogger.Log("[MainWindow] Executing dashboard update command");
                                    await viewModel.UpdateDashboardCommand.ExecuteAsync(null);
                                    DebugLogger.Log("[MainWindow] Dashboard update command completed");
                                }
                                else
                                {
                                    DebugLogger.Log("[MainWindow] Skipping dashboard update - conditions changed");
                                }
                            }
                            catch (Exception ex)
                            {
                                DebugLogger.Log($"[MainWindow] Dashboard update failed: {ex.Message}");
                                DebugLogger.Log($"[MainWindow] Stack trace: {ex.StackTrace}");
                            }
                        });
                    }
                    else
                    {
                        DebugLogger.Log($"[MainWindow] Skipping dashboard update: PacketCount={viewModel.PacketCount}, IsAnalyzing={viewModel.IsAnalyzing}");
                    }
                }

                // Log tab switch completion
                var timestamp2 = DateTime.Now.ToString("HH:mm:ss.fff");
                DebugLogger.Log($"[{timestamp2}] [TAB-SWITCH] Tab '{header}' - END (handler complete)");
            }
        }
        catch (Exception ex)
        {
            var timestamp3 = DateTime.Now.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{timestamp3}] [TAB-SWITCH] ERROR in tab selection changed: {ex.Message}");
        }
    }

    /// <summary>
    /// Animates tab content with a smooth fade-in effect.
    /// </summary>
    private static async Task AnimateTabContentFadeIn(Control content)
    {
        const int durationMs = 200;
        const int steps = 16;
        var stepDelay = durationMs / steps;

        // Start from invisible
        content.Opacity = 0;

        for (int i = 1; i <= steps; i++)
        {
            var t = (double)i / steps;
            // Ease-out cubic for smooth deceleration
            var eased = 1 - Math.Pow(1 - t, 3);
            content.Opacity = eased;
            await Task.Delay(stepDelay);
        }

        // Ensure final state
        content.Opacity = 1;
    }

    /// <summary>
    /// Handles Browse button click - opens file picker for PCAP files.
    /// Uses fire-and-forget pattern with exception handling to avoid async void.
    /// </summary>
    private void BrowseButton_Click(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel is null || DataContext is not MainWindowViewModel viewModel)
        {
            DebugLogger.Log("[MainWindow] TopLevel or ViewModel not available");
            return;
        }

        _ = HandleBrowseButtonClickAsync(topLevel, viewModel);
    }

    private async Task HandleBrowseButtonClickAsync(TopLevel topLevel, MainWindowViewModel viewModel)
    {
        try
        {
            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Select PCAP File",
                AllowMultiple = false,
                FileTypeFilter =
                [
                    new FilePickerFileType("PCAP Files")
                    {
                        Patterns = ["*.pcap", "*.pcapng", "*.cap"]
                    },
                    new FilePickerFileType("All Files")
                    {
                        Patterns = ["*.*"]
                    }
                ]
            });

            if (files.Count > 0)
            {
                var selectedFile = files[0];
                var filePath = selectedFile.Path.LocalPath;

                // Update ViewModel's FileManager (CurrentFile property triggers FileLoaded event)
                viewModel.FileManager.CurrentFile = filePath;

                DebugLogger.Log($"[MainWindow] File selected: {filePath}");

                // Update status
                viewModel.UIState.UpdateStatus($"File loaded: {Path.GetFileName(filePath)}", ThemeColorHelper.GetColorHex("ColorSuccess", "#4CAF50"));
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Browse error: {ex.Message}");
            viewModel.UIState.UpdateStatus($"Error selecting file: {ex.Message}", ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252"));
        }
    }

    /// <summary>
    /// Handles filter button click.
    /// Uses fire-and-forget pattern with exception handling to avoid async void.
    /// </summary>
    private void OnFilterButtonClick(object? sender, RoutedEventArgs e)
    {
        if (DataContext is MainWindowViewModel viewModel)
        {
            _ = HandleFilterButtonClickAsync(viewModel);
        }
    }

    private async Task HandleFilterButtonClickAsync(MainWindowViewModel viewModel)
    {
        try
        {
            var filterDialog = new FilterDialog
            {
                DataContext = viewModel.FilterViewModel
            };

            await filterDialog.ShowDialogWithAnimation(this);
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error in OnFilterButtonClick: {ex.Message}");
        }
    }
    

    // DEFERRED: Keyboard shortcuts - API alignment needed
    /*
    private void SetupKeyboardShortcuts()
    {
        try
        {
            if (DataContext is MainWindowViewModel viewModel)
            {
                // Create keyboard shortcut service
                var shortcutService = new KeyboardShortcutService(viewModel);
                viewModel.KeyboardShortcuts = shortcutService;

                // Add global key down handler
                this.KeyDown += OnWindowKeyDown;

                DebugLogger.Log("[MainWindow] Keyboard shortcuts initialized");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error setting up keyboard shortcuts: {ex.Message}");
        }
    }

    private void OnWindowKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is MainWindowViewModel viewModel)
        {
            // Let the keyboard shortcut service handle the key event
            if (viewModel.KeyboardShortcuts?.HandleKeyDown(e) == true)
            {
                // Shortcut was handled, no further processing needed
                return;
            }
        }
    }
    */

    public async Task<bool> TakeScreenshotAsync()
    {
        try
        {
            // Find the TabControl
            var tabControl = this.FindControl<TabControl>("MainTabControl");
            if (tabControl is null)
            {
                DebugLogger.Log("[MainWindow] Cannot find tab control for screenshot");
                return false;
            }
            
            // Get the selected tab content
            var selectedTab = tabControl.SelectedItem as TabItem;
            if (selectedTab?.Content is null)
            {
                DebugLogger.Log("[MainWindow] No tab selected for screenshot");
                return false;
            }
            
            // Get the content control
            var content = selectedTab.Content as Control;
            if (content is null)
            {
                DebugLogger.Log("[MainWindow] Cannot capture tab content");
                return false;
            }

            // CONSOLIDATED: Use unified render helper for DPI-aware, chart-safe capture
            using var bitmap = await RenderControlToBitmapAsync(content, layoutPasses: 2, delayPerPassMs: 50);
            if (bitmap is null)
            {
                DebugLogger.Log("[MainWindow] Failed to render content to bitmap");
                return false;
            }

            // Show save dialog
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save Screenshot",
                DefaultExtension = "jpg",
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("JPEG Image")
                    {
                        Patterns = new[] { "*.jpg", "*.jpeg" }
                    },
                    new FilePickerFileType("PNG Image")
                    {
                        Patterns = new[] { "*.png" }
                    }
                },
                SuggestedFileName = $"PCAPAnalyzer_Screenshot_{DateTime.Now:yyyyMMdd_HHmmss}.jpg"
            });

            if (file is null)
            {
                DebugLogger.Log("[MainWindow] Screenshot save cancelled");
                return false;
            }

            // Save the bitmap
            await using var stream = await file.OpenWriteAsync();
            SaveBitmapToStream(bitmap, stream, file.Name);

            DebugLogger.Log($"[MainWindow] Screenshot saved to {file.Name}");
            return true;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Screenshot error: {ex.Message}");
            DebugLogger.Log($"[MainWindow] Stack trace: {ex.StackTrace}");
            return false;
        }
    }
    
    private string GetTabName(int tabIndex)
    {
        // ✅ FIX: Tab index mapping matches actual MainWindow.axaml tab order
        // Current tab order: FileManager(0), PacketAnalysis(1), Dashboard(2), CountryTraffic(3), VoiceQoS(4), Threats(5), Anomalies(6), HostInventory(7), Compare(8), Reports(9)
        return tabIndex switch
        {
            0 => "FileManager",       // 📂 File Manager
            1 => "PacketAnalysis",    // 📦 Packet Analysis
            2 => "Dashboard",         // 📊 Dashboard
            3 => "CountryTraffic",    // 🌍 Country Traffic
            4 => "VoiceQoS",          // 📞 Voice / QoS
            5 => "Threats",           // 🛡️ Security Threats
            6 => "Anomalies",         // 🔬 Anomalies
            7 => "HostInventory",     // 🖥️ Host Inventory
            8 => "Compare",           // 🔍 Compare
            9 => "Reports",           // 📈 Reports
            _ => "Tab"
        };
    }
    
    private string GetScreenshotFileName(int tabIndex)
    {
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var tabName = GetTabName(tabIndex);
        return $"{tabName}_{timestamp}.jpg";
    }
    
    public async Task<bool> TakeScreenshotForCurrentTabAsync(int currentTabIndex)
    {
        try
        {
            // Find the TabControl
            var tabControl = this.FindControl<TabControl>("MainTabControl");
            if (tabControl is null)
            {
                DebugLogger.Log("[MainWindow] Cannot find tab control for screenshot");
                return false;
            }

            // Get the current tab's content
            var tabItem = tabControl.Items.OfType<TabItem>().ElementAtOrDefault(currentTabIndex);
            if (tabItem?.Content is not Control visualContent)
            {
                DebugLogger.Log("[MainWindow] Tab content is not a visual element");
                return false;
            }

            // Show save dialog
            var storageProvider = this.StorageProvider;
            if (storageProvider is null)
            {
                DebugLogger.Log("[MainWindow] Storage provider not available");
                return false;
            }

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var tabName = GetTabName(currentTabIndex);
            var defaultFileName = $"{tabName}_{timestamp}.jpg";

            var file = await storageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save Screenshot",
                DefaultExtension = "jpg",
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("JPEG Image")
                    {
                        Patterns = new[] { "*.jpg", "*.jpeg" }
                    },
                    new FilePickerFileType("PNG Image")
                    {
                        Patterns = new[] { "*.png" }
                    }
                },
                SuggestedFileName = defaultFileName
            });

            if (file is null)
            {
                DebugLogger.Log("[MainWindow] User cancelled save dialog");
                return false;
            }

            // CONSOLIDATED: Use unified render helpers for DPI-aware, chart-safe capture
            var scrollViewer = visualContent as ScrollViewer ?? FindScrollViewer(visualContent);
            RenderTargetBitmap? bitmap = null;

            try
            {
                bitmap = scrollViewer is not null
                    ? await RenderScrollableContentToBitmapAsync(scrollViewer, layoutPasses: 3, delayPerPassMs: 100)
                    : await RenderControlToBitmapAsync(visualContent, layoutPasses: 2, delayPerPassMs: 50);

                if (bitmap is null)
                {
                    DebugLogger.Log("[MainWindow] Failed to capture visual");
                    return false;
                }

                // Save to file
                await using var stream = await file.OpenWriteAsync();
                SaveBitmapToStream(bitmap, stream, file.Name);

                DebugLogger.Log($"[MainWindow] Screenshot saved to: {file.Path}");
                return true;
            }
            finally
            {
                bitmap?.Dispose();
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Screenshot error: {ex}");
            return false;
        }
    }
    
    public async Task<bool> TakeFullScreenshotAsync(int targetTabIndex)
    {
        try
        {
            // Find the TabControl
            var tabControl = this.FindControl<TabControl>("MainTabControl");
            if (tabControl is null)
            {
                DebugLogger.Log("[MainWindow] Cannot find tab control for screenshot");
                return false;
            }
            
            // Save current tab index
            var currentTabIndex = tabControl.SelectedIndex;
            
            // Switch to target tab if specified
            if (targetTabIndex >= 0 && targetTabIndex < tabControl.ItemCount)
            {
                tabControl.SelectedIndex = targetTabIndex;
                // FIXED: Increased wait time for tab to render, especially for complex tabs
                await Task.Delay(300);
            }

            // Get the selected tab content
            var selectedTab = tabControl.SelectedItem as TabItem;
            if (selectedTab?.Content is null)
            {
                DebugLogger.Log("[MainWindow] No tab selected for screenshot");
                return false;
            }

            // Get the content control
            var content = selectedTab.Content as Control;
            if (content is null)
            {
                DebugLogger.Log("[MainWindow] Cannot capture tab content");
                return false;
            }

            // CONSOLIDATED: Use unified render helpers for DPI-aware, chart-safe capture
            var scrollViewer = content as ScrollViewer ?? FindScrollViewer(content);
            RenderTargetBitmap? bitmap = null;

            try
            {
                if (scrollViewer is not null)
                {
                    // Full page capture with scroll-to-top for virtualized content
                    bitmap = await RenderScrollableContentToBitmapAsync(
                        scrollViewer,
                        layoutPasses: 4,
                        delayPerPassMs: 150,
                        scrollToTop: true);
                }
                else
                {
                    // Non-scrollable content - prefer UserControl itself over just content
                    var targetControl = content is UserControl ? content : content;
                    DebugLogger.Log("[MainWindow] No ScrollViewer found, capturing visible content");
                    bitmap = await RenderControlToBitmapAsync(targetControl, layoutPasses: 2, delayPerPassMs: 100);
                }

                if (bitmap is null)
                {
                    DebugLogger.Log("[MainWindow] Failed to capture content");
                    return false;
                }

                // Show save dialog
                var storage = StorageProvider;
                if (storage is null)
                {
                    DebugLogger.Log("[MainWindow] Storage provider not available");
                    return false;
                }

                var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
                {
                    Title = "Save Full Page Screenshot",
                    DefaultExtension = "jpg",
                    FileTypeChoices = new[]
                    {
                        new FilePickerFileType("JPEG Image") { Patterns = new[] { "*.jpg", "*.jpeg" } },
                        new FilePickerFileType("PNG Image") { Patterns = new[] { "*.png" } }
                    },
                    SuggestedFileName = GetScreenshotFileName(targetTabIndex >= 0 ? targetTabIndex : tabControl.SelectedIndex)
                });

                if (file is null)
                {
                    DebugLogger.Log("[MainWindow] Screenshot save cancelled");
                    // Restore original tab
                    if (targetTabIndex >= 0)
                        tabControl.SelectedIndex = currentTabIndex;
                    return false;
                }

                // Save the bitmap
                await using var stream = await file.OpenWriteAsync();
                SaveBitmapToStream(bitmap, stream, file.Name);

                DebugLogger.Log($"[MainWindow] Full screenshot saved to {file.Name}");

                // Restore original tab
                if (targetTabIndex >= 0)
                    tabControl.SelectedIndex = currentTabIndex;

                return true;
            }
            finally
            {
                bitmap?.Dispose();
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Full screenshot error: {ex.Message}");
            DebugLogger.Log($"[MainWindow] Stack trace: {ex.StackTrace}");
            return false;
        }
    }
    
    private ScrollViewer? FindScrollViewer(Control control)
    {
        // Recursively search for ScrollViewer in the visual tree
        if (control is ScrollViewer sv)
            return sv;
            
        if (control is Panel panel)
        {
            foreach (var child in panel.Children)
            {
                if (child is Control childControl)
                {
                    var result = FindScrollViewer(childControl);
                    if (result is not null)
                        return result;
                }
            }
        }
        else if (control is ContentControl cc && cc.Content is Control content)
        {
            return FindScrollViewer(content);
        }
        else if (control is Decorator decorator && decorator.Child is Control child)
        {
            return FindScrollViewer(child);
        }
        else if (control is UserControl userControl)
        {
            // Special handling for UserControl - look at its Content
            if (userControl.Content is Control ucContent)
                return FindScrollViewer(ucContent);
        }
        
        return null;
    }
    
    #region Screenshot DPI Helpers

    /// <summary>
    /// Gets DPI-aware parameters for RenderTargetBitmap creation.
    ///
    /// CRITICAL: Avalonia's Control.Bounds are in DIPs (Device Independent Pixels).
    /// RenderTargetBitmap expects physical pixels. On high-DPI displays (125%, 150%, 200%),
    /// using DIPs directly causes:
    /// - Blurry screenshots (undersized bitmap scaled up)
    /// - Black areas (bitmap smaller than rendered content)
    /// - Complete black screenshots (zero-size after truncation)
    /// </summary>
    /// <param name="control">The control to measure</param>
    /// <returns>Tuple of (PixelSize in physical pixels, DPI vector for RenderTargetBitmap)</returns>
    private (PixelSize size, Vector dpi) GetRenderTargetParams(Control control)
    {
        var scaling = RenderScaling;
        var width = Math.Max(1, (int)(control.Bounds.Width * scaling));
        var height = Math.Max(1, (int)(control.Bounds.Height * scaling));

        DebugLogger.Log($"[Screenshot] DPI scaling: {scaling:F2}, DIPs: {control.Bounds.Width:F0}x{control.Bounds.Height:F0}, Pixels: {width}x{height}");

        return (new PixelSize(width, height), new Vector(96 * scaling, 96 * scaling));
    }

    /// <summary>
    /// Gets DPI-aware parameters for a custom size (e.g., scrollable content).
    /// </summary>
    private (PixelSize size, Vector dpi) GetRenderTargetParams(double widthDips, double heightDips)
    {
        var scaling = RenderScaling;
        var width = Math.Max(1, (int)(widthDips * scaling));
        var height = Math.Max(1, (int)(heightDips * scaling));

        DebugLogger.Log($"[Screenshot] DPI scaling: {scaling:F2}, DIPs: {widthDips:F0}x{heightDips:F0}, Pixels: {width}x{height}");

        return (new PixelSize(width, height), new Vector(96 * scaling, 96 * scaling));
    }

    /// <summary>
    /// Ensures layout is complete before rendering. Critical for:
    /// - Virtualized controls (DataGrid, ItemsControl) that lazy-load content
    /// - Data-bound controls that update asynchronously
    /// - Complex layouts with nested measure/arrange passes
    /// </summary>
    private async Task EnsureLayoutCompleteAsync(Control control, int layoutPasses = 2, int delayPerPassMs = 100)
    {
        for (int i = 0; i < layoutPasses; i++)
        {
            control.InvalidateMeasure();
            control.InvalidateArrange();
            control.InvalidateVisual();
            control.UpdateLayout();

            // Process pending UI operations by yielding to the dispatcher
            await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Render);

            if (delayPerPassMs > 0)
                await Task.Delay(delayPerPassMs);
        }
    }

    /// <summary>
    /// Forces all LiveCharts controls in the visual tree to redraw.
    /// LiveCharts2 uses GPU rendering which may not be captured by RenderTargetBitmap.
    /// Calling InvalidateVisual() forces a CPU render pass.
    /// </summary>
    private async Task ForceChartsRedrawAsync(Control root)
    {
        var charts = FindAllChartsInVisualTree(root);
        if (charts.Count == 0)
        {
            DebugLogger.Log("[Screenshot] No charts found in visual tree");
            return;
        }

        DebugLogger.Log($"[Screenshot] Found {charts.Count} charts, forcing redraw");

        foreach (var chart in charts)
        {
            chart.InvalidateVisual();
        }

        // Wait for GPU → CPU sync
        await Task.Delay(200);

        // Additional layout pass after chart invalidation
        root.UpdateLayout();
        await Dispatcher.UIThread.InvokeAsync(() => { }, DispatcherPriority.Render);
    }

    /// <summary>
    /// Finds all LiveCharts CartesianChart and PieChart controls in the visual tree.
    /// </summary>
    private List<Control> FindAllChartsInVisualTree(Control root)
    {
        var charts = new List<Control>();
        FindChartsRecursive(root, charts);
        return charts;
    }

    private void FindChartsRecursive(Control control, List<Control> charts)
    {
        // LiveCharts2 chart types
        var typeName = control.GetType().Name;
        if (typeName is "CartesianChart" or "PieChart" or "PolarChart" or "GeoMap")
        {
            charts.Add(control);
        }

        // Recurse into children
        if (control is Panel panel)
        {
            foreach (var child in panel.Children)
            {
                if (child is Control childControl)
                    FindChartsRecursive(childControl, charts);
            }
        }
        else if (control is ContentControl cc && cc.Content is Control content)
        {
            FindChartsRecursive(content, charts);
        }
        else if (control is Decorator decorator && decorator.Child is Control child)
        {
            FindChartsRecursive(child, charts);
        }
        else if (control is UserControl uc && uc.Content is Control ucContent)
        {
            FindChartsRecursive(ucContent, charts);
        }
        else if (control is ItemsControl itemsControl)
        {
            foreach (var item in itemsControl.GetRealizedContainers())
            {
                if (item is Control itemControl)
                    FindChartsRecursive(itemControl, charts);
            }
        }
    }

    /// <summary>
    /// Core rendering method that captures a control to a DPI-aware bitmap.
    /// Handles layout completion, chart redraw, and proper scaling.
    /// </summary>
    /// <param name="control">Control to render</param>
    /// <param name="widthDips">Width in DIPs (use null to auto-detect from control bounds)</param>
    /// <param name="heightDips">Height in DIPs (use null to auto-detect from control bounds)</param>
    /// <param name="layoutPasses">Number of layout invalidation passes</param>
    /// <param name="delayPerPassMs">Delay between layout passes</param>
    /// <returns>DPI-scaled RenderTargetBitmap (caller must dispose)</returns>
    private async Task<RenderTargetBitmap?> RenderControlToBitmapAsync(
        Control control,
        double? widthDips = null,
        double? heightDips = null,
        int layoutPasses = 2,
        int delayPerPassMs = 100)
    {
        // DIAGNOSTIC: Log control tree context
        var controlType = control.GetType().Name;
        var parentType = (control.Parent as Control)?.GetType().Name ?? "none";
        DebugLogger.Log($"[Screenshot] RenderControl: {controlType} (parent: {parentType})");
        DebugLogger.Log($"[Screenshot]   Bounds: {control.Bounds}, IsVisible: {control.IsVisible}, IsEffectivelyVisible: {control.IsEffectivelyVisible}");

        // Calculate dimensions
        var w = widthDips ?? control.Bounds.Width;
        var h = heightDips ?? control.Bounds.Height;

        if (w <= 0 || h <= 0)
        {
            DebugLogger.Log($"[Screenshot] ⚠️ Invalid dimensions: {w}x{h} - control may not be laid out yet");
            return null;
        }

        // Get DPI-aware parameters
        var (pixelSize, dpiVector) = GetRenderTargetParams(w, h);
        DebugLogger.Log($"[Screenshot]   DIPs: {w:F0}x{h:F0} → Pixels: {pixelSize.Width}x{pixelSize.Height} (DPI: {dpiVector.X:F0})");

        // Complete layout
        await EnsureLayoutCompleteAsync(control, layoutPasses, delayPerPassMs);
        DebugLogger.Log($"[Screenshot]   Layout complete ({layoutPasses} passes, {delayPerPassMs}ms/pass)");

        // Force chart redraw
        await ForceChartsRedrawAsync(control);

        // Render
        var bitmap = new RenderTargetBitmap(pixelSize, dpiVector);
        bitmap.Render(control);
        DebugLogger.Log($"[Screenshot]   ✓ Rendered to {pixelSize.Width}x{pixelSize.Height} bitmap");

        return bitmap;
    }

    /// <summary>
    /// Captures the full scrollable content of a ScrollViewer.
    /// Measures content, adjusts scroll position, and renders the entire content.
    /// </summary>
    /// <param name="scrollViewer">ScrollViewer to capture</param>
    /// <param name="layoutPasses">Layout passes for content</param>
    /// <param name="delayPerPassMs">Delay between layout passes</param>
    /// <param name="scrollToTop">Whether to scroll to top before capture (restores position after)</param>
    private async Task<RenderTargetBitmap?> RenderScrollableContentToBitmapAsync(
        ScrollViewer scrollViewer,
        int layoutPasses = 3,
        int delayPerPassMs = 100,
        bool scrollToTop = false)
    {
        if (scrollViewer.Content is not Control scrollContent)
        {
            DebugLogger.Log("[Screenshot] ⚠️ ScrollViewer has no content");
            return null;
        }

        // DIAGNOSTIC: Log scrollviewer state
        var contentType = scrollContent.GetType().Name;
        DebugLogger.Log($"[Screenshot] RenderScrollableContent: ScrollViewer → {contentType}");
        DebugLogger.Log($"[Screenshot]   Viewport: {scrollViewer.Viewport}, Extent: {scrollViewer.Extent}");
        DebugLogger.Log($"[Screenshot]   ScrollOffset: {scrollViewer.Offset}, scrollToTop: {scrollToTop}");

        // First layout pass on content and scrollviewer
        await EnsureLayoutCompleteAsync(scrollContent, layoutPasses, delayPerPassMs);
        await EnsureLayoutCompleteAsync(scrollViewer, layoutPasses: 1, delayPerPassMs: 50);
        DebugLogger.Log($"[Screenshot]   Layout complete ({layoutPasses} passes, {delayPerPassMs}ms/pass)");

        // Measure content to get full size
        var measureSize = new Size(scrollViewer.Viewport.Width, double.PositiveInfinity);
        scrollContent.Measure(measureSize);
        var contentSize = scrollContent.DesiredSize;
        var viewportSize = scrollViewer.Viewport;

        // Calculate full size in DIPs
        var fullWidthDips = Math.Max(viewportSize.Width, contentSize.Width);
        var fullHeightDips = Math.Max(contentSize.Height, viewportSize.Height);

        // DIAGNOSTIC: Log measurement results
        DebugLogger.Log($"[Screenshot]   DesiredSize: {contentSize}, Viewport: {viewportSize}");
        DebugLogger.Log($"[Screenshot]   Calculated: {fullWidthDips:F0}x{fullHeightDips:F0} DIPs");

        // Ensure minimum size
        if (fullWidthDips <= 0 || fullHeightDips <= 0)
        {
            DebugLogger.Log($"[Screenshot] ⚠️ Invalid content size, using fallback from Bounds");
            fullWidthDips = Math.Max(scrollViewer.Bounds.Width, 1920);
            fullHeightDips = Math.Max(scrollViewer.Bounds.Height, 2000);
        }

        // Get DPI-aware parameters
        var (pixelSize, dpiVector) = GetRenderTargetParams(fullWidthDips, fullHeightDips);
        DebugLogger.Log($"[Screenshot]   DIPs: {fullWidthDips:F0}x{fullHeightDips:F0} → Pixels: {pixelSize.Width}x{pixelSize.Height} (DPI: {dpiVector.X:F0})");

        // Handle scroll position if requested
        Vector? originalOffset = null;
        if (scrollToTop)
        {
            originalOffset = scrollViewer.Offset;
            scrollViewer.Offset = new Vector(0, 0);
            DebugLogger.Log($"[Screenshot]   Scrolled to top (was: {originalOffset})");
            await Task.Delay(300); // Wait for virtualized content after scroll
            await EnsureLayoutCompleteAsync(scrollContent, layoutPasses: 1, delayPerPassMs: 100);
        }

        // Force chart redraw before capture
        await ForceChartsRedrawAsync(scrollContent);

        // Render
        var bitmap = new RenderTargetBitmap(pixelSize, dpiVector);
        bitmap.Render(scrollContent);
        DebugLogger.Log($"[Screenshot]   ✓ Rendered to {pixelSize.Width}x{pixelSize.Height} bitmap");

        // Restore scroll position if we changed it
        if (originalOffset.HasValue)
        {
            scrollViewer.Offset = originalOffset.Value;
            DebugLogger.Log($"[Screenshot]   Restored scroll position to {originalOffset}");
        }

        return bitmap;
    }

    #endregion

    private void SaveBitmapToStream(RenderTargetBitmap bitmap, System.IO.Stream stream, string fileName)
    {
        try
        {
            if (fileName.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) || 
                fileName.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase))
            {
                // Convert to JPEG using SkiaSharp
                using var skBitmap = ConvertToSkBitmap(bitmap);
                using var data = skBitmap.Encode(SKEncodedImageFormat.Jpeg, 95);
                data.SaveTo(stream);
                DebugLogger.Log($"[MainWindow] Saved as JPEG with quality 95");
            }
            else
            {
                // Default to PNG
                bitmap.Save(stream);
                DebugLogger.Log($"[MainWindow] Saved as PNG");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error saving bitmap: {ex.Message}");
            // Fallback to PNG if JPEG conversion fails
            bitmap.Save(stream);
        }
    }
    
    private SKBitmap ConvertToSkBitmap(RenderTargetBitmap source)
    {
        // Create a memory stream and save the bitmap as PNG first
        using var memoryStream = new System.IO.MemoryStream();
        source.Save(memoryStream);
        memoryStream.Seek(0, System.IO.SeekOrigin.Begin);

        // Load into SkiaSharp
        using var skData = SKData.Create(memoryStream);
        using var codec = SKCodec.Create(skData);
        var info = new SKImageInfo(codec.Info.Width, codec.Info.Height, SKColorType.Rgba8888, SKAlphaType.Premul);
        var skBitmap = new SKBitmap(info);
        codec.GetPixels(info, skBitmap.GetPixels());

        return skBitmap;
    }

    /// <summary>
    /// Handles click on the dark overlay behind DrillDown popup - closes the popup
    /// </summary>
    private void OnDrillDownOverlayPressed(object? sender, PointerPressedEventArgs e)
    {
        if (DataContext is MainWindowViewModel vm && vm.Charts?.DrillDown is not null)
        {
            vm.Charts.DrillDown.IsVisible = false;
        }
    }

    /// <summary>
    /// Handles click on the popup itself - prevents event from bubbling to overlay
    /// </summary>
    private void OnDrillDownPopupPressed(object? sender, PointerPressedEventArgs e)
    {
        // Stop propagation so clicking on popup doesn't close it
        e.Handled = true;
    }
}
