using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Rendering;
using PCAPAnalyzer.UI.Controls;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Views
{
    public partial class GeographicMapView : UserControl
    {
        private ContinentMapControl? _mapControl;

        public GeographicMapView()
        {
            InitializeComponent();

            DataContextChanged += OnDataContextChanged;
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
            _mapControl = this.FindControl<ContinentMapControl>("MapControl");
        }
        
        private void OnDataContextChanged(object? sender, EventArgs e)
        {
            if (DataContext is GeographicMapViewModel viewModel)
            {
                viewModel.ScreenshotRequested += OnScreenshotRequested;
            }
        }
        
        private async void OnScreenshotRequested(string filePath)
        {
            try
            {
                if (_mapControl is null) 
                {
                    DebugLogger.Log($"[EnhancedMapView] Map control is null, cannot take screenshot");
                    return;
                }
                
                // Ensure the control has valid bounds
                if (_mapControl.Bounds.Width <= 0 || _mapControl.Bounds.Height <= 0)
                {
                    DebugLogger.Log($"[EnhancedMapView] Map control has invalid bounds: {_mapControl.Bounds}");
                    return;
                }
                
                // Render the control to a bitmap
                var pixelSize = new PixelSize((int)_mapControl.Bounds.Width, (int)_mapControl.Bounds.Height);
                var dpi = new Vector(96, 96);
                
                using (var bitmap = new RenderTargetBitmap(pixelSize, dpi))
                {
                    _mapControl.Measure(new Size(pixelSize.Width, pixelSize.Height));
                    _mapControl.Arrange(new Rect(0, 0, pixelSize.Width, pixelSize.Height));
                    
                    // Force a render
                    await Task.Delay(100);
                    
                    bitmap.Render(_mapControl);
                    
                    // Save to file using stream
                    using (var stream = File.Create(filePath))
                    {
                        bitmap.Save(stream);
                    }
                    
                    DebugLogger.Log($"[EnhancedMapView] Screenshot saved to: {filePath}");
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[EnhancedMapView] Screenshot error: {ex.Message}");
                DebugLogger.Log($"[EnhancedMapView] Stack trace: {ex.StackTrace}");
            }
        }
    }
}