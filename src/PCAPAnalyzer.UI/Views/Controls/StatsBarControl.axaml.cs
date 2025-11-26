using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.LogicalTree;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Views.Controls;

public partial class StatsBarControl : UserControl
{
    private const double RESPONSIVE_BREAKPOINT = 1400; // Width threshold for column adjustment
    private Window? _parentWindow;
    private int _baseColumnCount = 4; // Track original column count set by tab

    public StatsBarControl()
    {
        InitializeComponent();

        // Subscribe to AttachedToLogicalTree to find parent window
        AttachedToLogicalTree += OnAttachedToLogicalTree;
        DetachedFromLogicalTree += OnDetachedFromLogicalTree;
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        // Store base column count when DataContext is set
        if (DataContext is StatsBarControlViewModel viewModel)
        {
            _baseColumnCount = viewModel.ColumnCount;
        }
    }

    private void OnAttachedToLogicalTree(object? sender, LogicalTreeAttachmentEventArgs e)
    {
        // Find parent window
        _parentWindow = this.FindLogicalAncestorOfType<Window>();

        if (_parentWindow != null)
        {
            // Store base column count from ViewModel
            if (DataContext is StatsBarControlViewModel viewModel)
            {
                _baseColumnCount = viewModel.ColumnCount;
            }

            // Subscribe to window resize events
            _parentWindow.PropertyChanged += OnWindowPropertyChanged;

            // Set initial column count based on current window size
            UpdateColumnCount(_parentWindow.Bounds.Width);
        }
    }

    private void OnDetachedFromLogicalTree(object? sender, LogicalTreeAttachmentEventArgs e)
    {
        // Unsubscribe to prevent memory leaks
        if (_parentWindow != null)
        {
            _parentWindow.PropertyChanged -= OnWindowPropertyChanged;
            _parentWindow = null;
        }
    }

    private void OnWindowPropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
    {
        // Monitor Bounds property for window size changes
        if (e.Property.Name == nameof(Window.Bounds))
        {
            if (e.NewValue is Rect bounds)
            {
                UpdateColumnCount(bounds.Width);
            }
        }
    }

    private void UpdateColumnCount(double windowWidth)
    {
        if (DataContext is not StatsBarControlViewModel viewModel)
            return;

        // Apply responsive behavior: reduce columns on narrow windows
        var adjustedColumns = windowWidth < RESPONSIVE_BREAKPOINT
            ? Math.Max(3, _baseColumnCount - 1) // Reduce by 1, but minimum 3 columns
            : _baseColumnCount;                   // Use original column count

        // Only update if changed (prevents unnecessary re-layouts)
        if (viewModel.ColumnCount != adjustedColumns)
        {
            viewModel.ColumnCount = adjustedColumns;
        }
    }
}
