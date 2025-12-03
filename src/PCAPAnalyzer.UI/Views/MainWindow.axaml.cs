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
using SkiaSharp;
using PCAPAnalyzer.Core.Monitoring;
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

            // Setup drag & drop handlers
            SetupDragDropHandlers();

            // Setup keyboard shortcut handlers (DEFERRED - API alignment needed)
            // SetupKeyboardShortcuts();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error in constructor: {ex.Message}");
            DebugLogger.Log($"[MainWindow] Stack trace: {ex.StackTrace}");

            if (ex.InnerException != null)
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
        if (tabControl != null)
        {
            tabControl.SelectionChanged += OnTabSelectionChanged;
        }

        // Subscribe to Charts ViewModel property changes to reset highlight when series are rebuilt
        if (DataContext is MainWindowViewModel vm && vm.Charts != null)
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
    
    private void OnTabSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        try
        {
            if (sender is TabControl tabControl && DataContext is MainWindowViewModel viewModel)
            {
                var selectedTab = tabControl.SelectedItem as TabItem;
                if (selectedTab != null)
                {
                    var header = selectedTab.Header?.ToString() ?? "";
                    var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                    DebugLogger.Log($"[{timestamp}] [TAB-SWITCH] User clicked tab: '{header}' - BEGIN");

                    // If switching to Dashboard tab, ensure it's safe to display
                    if (header.Contains("Dashboard", StringComparison.Ordinal))
                    {
                        DebugLogger.Log("[MainWindow] Dashboard tab selected");

                        // Ensure dashboard is initialized
                        if (viewModel.DashboardViewModel == null)
                        {
                            DebugLogger.Log("[MainWindow] Dashboard not initialized, creating new instance");
                            try
                            {
                                viewModel.DashboardViewModel = new DashboardViewModel();
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
                            _ = System.Threading.Tasks.Task.Run(async () =>
                            {
                                try
                                {
                                    // Add a small delay to let UI stabilize
                                    await System.Threading.Tasks.Task.Delay(100);

                                    // Check again that we should update
                                    if (viewModel.DashboardViewModel != null && !viewModel.IsAnalyzing)
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
        }
        catch (Exception ex)
        {
            var timestamp3 = DateTime.Now.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{timestamp3}] [TAB-SWITCH] ERROR in tab selection changed: {ex.Message}");
        }
    }

    /// <summary>
    /// Handles Browse button click - opens file picker for PCAP files
    /// </summary>
    private async void BrowseButton_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            var topLevel = TopLevel.GetTopLevel(this);
            if (topLevel == null || DataContext is not MainWindowViewModel viewModel)
            {
                DebugLogger.Log("[MainWindow] TopLevel or ViewModel not available");
                return;
            }

            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Select PCAP File",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("PCAP Files")
                    {
                        Patterns = new[] { "*.pcap", "*.pcapng", "*.cap" }
                    },
                    new FilePickerFileType("All Files")
                    {
                        Patterns = new[] { "*.*" }
                    }
                }
            });

            if (files.Count > 0)
            {
                var selectedFile = files[0];
                var filePath = selectedFile.Path.LocalPath;

                // Update ViewModel's FileManager (CurrentFile property triggers FileLoaded event)
                viewModel.FileManager.CurrentFile = filePath;

                DebugLogger.Log($"[MainWindow] File selected: {filePath}");

                // Update status
                viewModel.UIState.UpdateStatus($"File loaded: {Path.GetFileName(filePath)}", "#4CAF50");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Browse error: {ex.Message}");
            if (DataContext is MainWindowViewModel vm)
            {
                vm.UIState.UpdateStatus($"Error selecting file: {ex.Message}", "#FF5252");
            }
        }
    }

    private async void OnFilterButtonClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (DataContext is MainWindowViewModel viewModel)
            {
                var filterDialog = new FilterDialog
                {
                    DataContext = viewModel.FilterViewModel
                };
                
                await filterDialog.ShowDialog(this);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error in OnFilterButtonClick: {ex.Message}");
        }
    }
    
    private void SetupDragDropHandlers()
    {
        try
        {
            var dragDropArea = this.FindControl<Border>("DragDropArea");
            if (dragDropArea != null)
            {
                dragDropArea.AddHandler(DragDrop.DragEnterEvent, OnDragEnter);
                dragDropArea.AddHandler(DragDrop.DragLeaveEvent, OnDragLeave);
                dragDropArea.AddHandler(DragDrop.DragOverEvent, OnDragOver);
                dragDropArea.AddHandler(DragDrop.DropEvent, OnDrop);
                dragDropArea.PointerPressed += OnDragDropAreaClick;
                DebugLogger.Log("[MainWindow] Drag & drop handlers setup complete");
            }
            else
            {
                DebugLogger.Log("[MainWindow] Warning: DragDropArea not found");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error setting up drag & drop: {ex.Message}");
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
    
    private void OnDragEnter(object? sender, DragEventArgs e)
    {
        var files = e.DataTransfer.TryGetFiles();
        if (files != null && files.Any())
        {
            var file = files.First();
            if (file.Name.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) ||
                file.Name.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            {
                e.DragEffects = DragDropEffects.Copy;
                if (sender is Border border)
                {
                    border.Classes.Add("drag-over");
                }
                return;
            }
        }
        e.DragEffects = DragDropEffects.None;
    }
    
    private void OnDragLeave(object? sender, DragEventArgs e)
    {
        if (sender is Border border)
        {
            border.Classes.Remove("drag-over");
        }
    }
    
    private void OnDragOver(object? sender, DragEventArgs e)
    {
        var files = e.DataTransfer.TryGetFiles();
        if (files != null && files.Any())
        {
            var file = files.First();
            if (file.Name.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) ||
                file.Name.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
            {
                e.DragEffects = DragDropEffects.Copy;
                return;
            }
        }
        e.DragEffects = DragDropEffects.None;
    }
    
    private async void OnDrop(object? sender, DragEventArgs e)
    {
        try
        {
            if (sender is Border border)
            {
                border.Classes.Remove("drag-over");
            }
            
            var files = e.DataTransfer.TryGetFiles();
            if (files != null && files.Any())
            {
                var file = files.First();
                if (file.Name.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) ||
                    file.Name.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase))
                {
                    if (DataContext is MainWindowViewModel viewModel)
                    {
                        var path = file.Path?.LocalPath ?? file.Name;
                        DebugLogger.Log($"[MainWindow] File dropped: {path}");
                        await viewModel.LoadCaptureAsync(path);
                        e.Handled = true;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error in OnDrop: {ex.Message}");
        }
    }
    
    private async void OnDragDropAreaClick(object? sender, PointerPressedEventArgs e)
    {
        try
        {
            if (DataContext is MainWindowViewModel viewModel)
            {
                await viewModel.FileManager.OpenFileCommand.ExecuteAsync(null);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindow] Error in OnDragDropAreaClick: {ex.Message}");
        }
    }
    
    public async Task<bool> TakeScreenshotAsync()
    {
        try
        {
            // Find the TabControl
            var tabControl = this.FindControl<TabControl>("MainTabControl");
            if (tabControl == null)
            {
                DebugLogger.Log("[MainWindow] Cannot find tab control for screenshot");
                return false;
            }
            
            // Get the selected tab content
            var selectedTab = tabControl.SelectedItem as TabItem;
            if (selectedTab?.Content == null)
            {
                DebugLogger.Log("[MainWindow] No tab selected for screenshot");
                return false;
            }
            
            // Get the content control
            var content = selectedTab.Content as Control;
            if (content == null)
            {
                DebugLogger.Log("[MainWindow] Cannot capture tab content");
                return false;
            }
            
            // Calculate the size
            var pixelSize = new PixelSize((int)content.Bounds.Width, (int)content.Bounds.Height);
            if (pixelSize.Width <= 0 || pixelSize.Height <= 0)
            {
                DebugLogger.Log("[MainWindow] Invalid content size for screenshot");
                return false;
            }
            
            // Render to bitmap
            using var bitmap = new RenderTargetBitmap(pixelSize, new Vector(96, 96));
            content.Measure(content.Bounds.Size);
            content.Arrange(new Rect(content.Bounds.Size));
            bitmap.Render(content);

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

            if (file == null)
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
        // Current tab order: FileManager(0), PacketAnalysis(1), Dashboard(2), Threats(3), Anomalies(4), HostInventory(5), VoiceQoS(6), CountryTraffic(7), Compare(8), Reports(9)
        return tabIndex switch
        {
            0 => "FileManager",       // 📂 File Manager
            1 => "PacketAnalysis",    // 📦 Packet Analysis
            2 => "Dashboard",         // 📊 Dashboard
            3 => "Threats",           // 🛡️ Security Threats
            4 => "Anomalies",         // 🔬 Anomalies
            5 => "HostInventory",     // 🖥️ Host Inventory
            6 => "VoiceQoS",          // 📞 Voice / QoS
            7 => "CountryTraffic",    // 🌍 Country Traffic
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
            if (tabControl == null)
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
            if (storageProvider == null)
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

            if (file == null)
            {
                DebugLogger.Log("[MainWindow] User cancelled save dialog");
                return false;
            }

            // Check if the content is or contains a ScrollViewer
            var scrollViewer = visualContent as ScrollViewer ?? FindScrollViewer(visualContent);
            RenderTargetBitmap? bitmap = null;

            try
            {
                if (scrollViewer != null && scrollViewer.Content is Control scrollContent)
                {
                    DebugLogger.Log("[MainWindow] Found ScrollViewer, capturing full scrollable content");

                    // Force layout update
                    scrollContent.InvalidateMeasure();
                    scrollContent.InvalidateArrange();
                    scrollViewer.InvalidateMeasure();
                    scrollViewer.InvalidateArrange();

                    // Force rendering of all content
                    scrollContent.UpdateLayout();
                    scrollViewer.UpdateLayout();
                    await Task.Delay(300); // Increased delay for better rendering

                    // Get the actual size of the content
                    var measureSize = new Size(scrollViewer.Viewport.Width, double.PositiveInfinity);
                    scrollContent.Measure(measureSize);
                    var contentSize = scrollContent.DesiredSize;
                    var viewportSize = scrollViewer.Viewport;

                    // Use the actual measured size for height, viewport width
                    var fullSize = new PixelSize(
                        Math.Max((int)viewportSize.Width, (int)contentSize.Width),
                        Math.Max((int)contentSize.Height, (int)viewportSize.Height)
                    );

                    // Ensure minimum size
                    if (fullSize.Width <= 0 || fullSize.Height <= 0)
                    {
                        DebugLogger.Log($"[MainWindow] Invalid full content size: {fullSize.Width}x{fullSize.Height}");
                        // Use reasonable defaults
                        fullSize = new PixelSize(
                            Math.Max((int)scrollViewer.Bounds.Width, 1920),
                            Math.Max((int)scrollViewer.Bounds.Height, 2000)
                        );
                    }

                    DebugLogger.Log($"[MainWindow] Creating bitmap with size: {fullSize.Width}x{fullSize.Height}");
                    bitmap = new RenderTargetBitmap(fullSize, new Vector(96, 96));
                    bitmap.Render(scrollContent);
                }
                else
                {
                    // Standard rendering for non-scrollable content
                    var size = new PixelSize((int)visualContent.Bounds.Width, (int)visualContent.Bounds.Height);
                    bitmap = new RenderTargetBitmap(size, new Vector(96, 96));
                    bitmap.Render(visualContent);
                }

                if (bitmap == null)
                {
                    DebugLogger.Log("[MainWindow] Failed to capture visual");
                    return false;
                }

                // Save to file (use existing SaveBitmapToStream method for proper JPEG conversion)
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
            if (tabControl == null)
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
                // Wait for the tab to render
                await Task.Delay(100);
            }
            
            // Get the selected tab content
            var selectedTab = tabControl.SelectedItem as TabItem;
            if (selectedTab?.Content == null)
            {
                DebugLogger.Log("[MainWindow] No tab selected for screenshot");
                return false;
            }
            
            // Get the content control
            var content = selectedTab.Content as Control;
            if (content == null)
            {
                DebugLogger.Log("[MainWindow] Cannot capture tab content");
                return false;
            }
            
            // Special handling for ScrollViewer content
            RenderTargetBitmap? bitmap = null;

            try
            {
                // Check if the content is or contains a ScrollViewer
                var scrollViewer = content as ScrollViewer ?? FindScrollViewer(content);

                if (scrollViewer != null && scrollViewer.Content is Control scrollContent)
                {
                    DebugLogger.Log("[MainWindow] Found ScrollViewer, capturing full scrollable content");

                    // Force complete layout cycle to ensure ItemsControls are realized
                    // FileManagerView uses ItemsControl for Analysis Stages which needs full realization
                    scrollContent.InvalidateMeasure();
                    scrollContent.InvalidateArrange();
                    scrollContent.InvalidateVisual();
                    scrollViewer.InvalidateMeasure();
                    scrollViewer.InvalidateArrange();
                    scrollViewer.InvalidateVisual();

                    // Force multiple layout passes to ensure ItemsControl content is realized
                    for (int i = 0; i < 3; i++)
                    {
                        scrollContent.UpdateLayout();
                        scrollViewer.UpdateLayout();
                        await Task.Delay(200); // Increased delay for better rendering
                    }

                    // Get the actual size of the content
                    // For Dashboard, we need to measure the StackPanel inside the ScrollViewer
                    var measureSize = new Size(scrollViewer.Viewport.Width, double.PositiveInfinity);
                    scrollContent.Measure(measureSize);
                    var contentSize = scrollContent.DesiredSize;
                    var viewportSize = scrollViewer.Viewport;

                    // Use the actual measured size for height, viewport width
                    var fullSize = new PixelSize(
                        Math.Max((int)viewportSize.Width, (int)contentSize.Width),
                        Math.Max((int)contentSize.Height, (int)viewportSize.Height)
                    );

                    // Ensure minimum size
                    if (fullSize.Width <= 0 || fullSize.Height <= 0)
                    {
                        DebugLogger.Log($"[MainWindow] Invalid full content size: {fullSize.Width}x{fullSize.Height}");
                        // Use reasonable defaults
                        fullSize = new PixelSize(
                            Math.Max((int)scrollViewer.Bounds.Width, 1920),
                            Math.Max((int)scrollViewer.Bounds.Height, 2000) // Increased height for dashboard
                        );
                    }

                    DebugLogger.Log($"[MainWindow] Capturing full content: {fullSize.Width}x{fullSize.Height}");
                    DebugLogger.Log($"[MainWindow] Content bounds: {scrollContent.Bounds}");
                    DebugLogger.Log($"[MainWindow] Content desired size: {contentSize}");

                    // Create bitmap for full content
                    bitmap = new RenderTargetBitmap(fullSize, new Vector(96, 96));

                    // Store original scroll position
                    var originalOffset = scrollViewer.Offset;

                    // Scroll to top to ensure all content is visible
                    scrollViewer.Offset = new Vector(0, 0);
                    await Task.Delay(100);

                    // Force one more layout pass after scrolling
                    scrollContent.UpdateLayout();
                    await Task.Delay(50);

                    // Render the content directly
                    // This works for all tabs including Dashboard
                    bitmap.Render(scrollContent);

                    // Restore scroll position
                    scrollViewer.Offset = originalOffset;
                }
                else
                {
                    // Fallback to regular screenshot for non-scrollable content
                    DebugLogger.Log("[MainWindow] No ScrollViewer found, capturing visible content");

                    // For UserControls, try to capture the UserControl itself, not just its content
                    var targetControl = content;
                    if (content is UserControl userControl)
                    {
                        DebugLogger.Log("[MainWindow] Capturing UserControl directly");
                        targetControl = userControl;
                    }

                    var pixelSize = new PixelSize((int)targetControl.Bounds.Width, (int)targetControl.Bounds.Height);

                    if (pixelSize.Width <= 0 || pixelSize.Height <= 0)
                    {
                        DebugLogger.Log($"[MainWindow] Invalid content size: {pixelSize.Width}x{pixelSize.Height}");
                        return false;
                    }

                    bitmap = new RenderTargetBitmap(pixelSize, new Vector(96, 96));
                    bitmap.Render(targetControl);
                }

                // Show save dialog
                var storage = StorageProvider;
                if (storage == null)
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

                if (file == null)
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
                    if (result != null)
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
        if (DataContext is MainWindowViewModel vm && vm.Charts?.DrillDown != null)
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
