using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Media.Imaging;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Implementation of IScreenshotService using Avalonia's RenderTargetBitmap.
    /// Cross-platform approach that works reliably on Windows, Linux, and WSL2.
    /// </summary>
    public class ScreenshotService : IScreenshotService
    {
        private Window? GetMainWindow()
        {
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                return desktop.MainWindow;
            }
            return null;
        }

        public async Task<bool> CaptureCurrentViewAsync(string? viewName = null)
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var fileName = string.IsNullOrEmpty(viewName)
                ? $"Screenshot_{timestamp}"
                : $"{viewName}_{timestamp}";

            return await CaptureWithFilenameAsync(fileName);
        }

        public async Task<bool> CaptureWithFilenameAsync(string fileName)
        {
            try
            {
                var window = GetMainWindow();
                if (window == null)
                {
                    DebugLogger.Log("[Screenshot] ERROR: Main window is null");
                    return false;
                }

                // Get window dimensions (client area, excluding window chrome)
                var bounds = window.Bounds;
                int width = (int)bounds.Width;
                int height = (int)bounds.Height;

                if (width <= 0 || height <= 0)
                {
                    DebugLogger.Log($"[Screenshot] ERROR: Invalid window size: {width}x{height}");
                    return false;
                }

                DebugLogger.Log($"[Screenshot] Window size: {width}x{height}");

                // Get the screenshot directory
                var directory = GetScreenshotDirectory();
                Directory.CreateDirectory(directory);
                var finalPath = Path.Combine(directory, $"{fileName}.png");

                // Must run on UI thread for Avalonia rendering
                await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() =>
                {
                    try
                    {
                        // Get the actual pixel size accounting for DPI scaling
                        var dpi = window.RenderScaling;
                        var pixelWidth = (int)(width * dpi);
                        var pixelHeight = (int)(height * dpi);

                        DebugLogger.Log($"[Screenshot] Render scaling: {dpi}, Pixel size: {pixelWidth}x{pixelHeight}");

                        // Create RenderTargetBitmap with proper DPI
                        var pixelSize = new PixelSize(pixelWidth, pixelHeight);
                        var dpiVector = new Vector(96 * dpi, 96 * dpi);

                        using var renderTarget = new RenderTargetBitmap(pixelSize, dpiVector);

                        // Render the window content (not the chrome)
                        // Use the window's visual child (the actual content)
                        if (window.Content is Control content)
                        {
                            renderTarget.Render(content);
                            DebugLogger.Log("[Screenshot] Rendered window content");
                        }
                        else
                        {
                            // Fallback: render the entire window
                            renderTarget.Render(window);
                            DebugLogger.Log("[Screenshot] Rendered entire window (fallback)");
                        }

                        // Save as PNG (lossless, better for UI screenshots)
                        renderTarget.Save(finalPath);
                        DebugLogger.Log($"[Screenshot] Saved: {finalPath}");
                    }
                    catch (Exception ex)
                    {
                        DebugLogger.Log($"[Screenshot] Render error: {ex.Message}");
                        throw;
                    }
                });

                return File.Exists(finalPath);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[Screenshot] ERROR: {ex.Message}");
                return false;
            }
        }

        public string GetScreenshotDirectory()
        {
            // Save to application directory
            var appDir = AppDomain.CurrentDomain.BaseDirectory;
            return Path.Combine(appDir, "Screenshots");
        }
    }
}
