using System;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace PCAPAnalyzer.UI.Controls
{
    public partial class PopupChartView : UserControl
    {
        public PopupChartView()
        {
            try
            {
                InitializeComponent();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error initializing PopupChartView: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                
                // Create a simple fallback UI if initialization fails
                try
                {
                    var textBlock = new TextBlock
                    {
                        Text = "Error loading chart view",
                        HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
                        VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
                    };
                    Content = textBlock;
                }
                catch (Exception fallbackEx)
                {
                    // Last resort: log fallback failure but don't crash
                    System.Diagnostics.Debug.WriteLine($"CRITICAL: Fallback UI creation failed: {fallbackEx.Message}");
                }
            }
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
    }
}