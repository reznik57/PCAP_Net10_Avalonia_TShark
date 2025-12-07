using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Media;
using System;
using System.Threading.Tasks;

namespace PCAPAnalyzer.UI.Utilities;

/// <summary>
/// Provides modern entrance animations for windows.
/// Usage: Call ShowWithAnimation() instead of Show() for secondary windows.
/// </summary>
public static class WindowAnimations
{
    private const int DurationMs = 200;
    private const int Steps = 20;
    private const double StartScale = 0.96;
    private const double StartOpacity = 0.0;

    /// <summary>
    /// Shows the window with a smooth fade+scale entrance animation.
    /// </summary>
    public static void ShowWithAnimation(this Window window, Window? owner = null)
    {
        PrepareForAnimation(window);

        if (owner is not null)
            window.Show(owner);
        else
            window.Show();

        _ = RunEntranceAnimationAsync(window);
    }

    /// <summary>
    /// Shows the window as a dialog with a smooth fade+scale entrance animation.
    /// </summary>
    public static async Task<TResult?> ShowDialogWithAnimation<TResult>(this Window window, Window owner)
    {
        PrepareForAnimation(window);
        window.Opened += OnWindowOpened;
        return await window.ShowDialog<TResult?>(owner);
    }

    /// <summary>
    /// Shows the window as a dialog with a smooth fade+scale entrance animation.
    /// </summary>
    public static async Task ShowDialogWithAnimation(this Window window, Window owner)
    {
        PrepareForAnimation(window);
        window.Opened += OnWindowOpened;
        await window.ShowDialog(owner);
    }

    private static void PrepareForAnimation(Window window)
    {
        window.Opacity = StartOpacity;
        window.RenderTransformOrigin = RelativePoint.Center;
        window.RenderTransform = new ScaleTransform(StartScale, StartScale);
    }

    private static void OnWindowOpened(object? sender, EventArgs e)
    {
        if (sender is Window window)
        {
            window.Opened -= OnWindowOpened;
            _ = RunEntranceAnimationAsync(window);
        }
    }

    private static async Task RunEntranceAnimationAsync(Window window)
    {
        try
        {
            var stepDelay = DurationMs / Steps;

            for (int i = 1; i <= Steps; i++)
            {
                var t = (double)i / Steps;
                var eased = EaseOutCubic(t);

                // Interpolate opacity: 0 -> 1
                window.Opacity = eased;

                // Interpolate scale: 0.96 -> 1.0
                var scale = StartScale + ((1.0 - StartScale) * eased);
                window.RenderTransform = new ScaleTransform(scale, scale);

                await Task.Delay(stepDelay);
            }

            // Ensure final state
            window.Opacity = 1;
            window.RenderTransform = new ScaleTransform(1, 1);
        }
        catch (Exception ex)
        {
            // Animation is cosmetic - don't crash
            System.Diagnostics.Debug.WriteLine($"Window animation error: {ex.Message}");
            window.Opacity = 1;
            window.RenderTransform = new ScaleTransform(1, 1);
        }
    }

    private static double EaseOutCubic(double t) => 1 - Math.Pow(1 - t, 3);
}
