using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views;

public partial class DetailedTableWindow : Window
{
    public DetailedTableWindow()
    {
        InitializeComponent();
    }
    
    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        
        // Set window size to 90% of parent window or screen
        if (Owner is not null)
        {
            Width = Owner.Bounds.Width * 0.9;
            Height = Owner.Bounds.Height * 0.9;
        }
        else
        {
            // Fallback to screen size
            var screen = Screens.Primary;
            if (screen is not null)
            {
                Width = screen.WorkingArea.Width * 0.8;
                Height = screen.WorkingArea.Height * 0.8;
            }
            else
            {
                // Default size if all else fails
                Width = 1200;
                Height = 800;
            }
        }
    }
    
    private void OnCloseClicked(object sender, RoutedEventArgs e)
    {
        Close();
    }
}