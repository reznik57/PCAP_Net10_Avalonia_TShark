using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;

namespace PCAPAnalyzer.UI.Views.Base
{
    /// <summary>
    /// Base class for all detail windows with common functionality.
    /// Handles disposal of IDisposable DataContext when window closes.
    /// </summary>
    public abstract class BaseDetailWindow : Window
    {
        protected BaseDetailWindow()
        {
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            InitializeHandlers();
        }

        private void InitializeHandlers()
        {
            KeyDown += OnKeyDown;
            Closed += OnWindowClosed;
        }

        /// <summary>
        /// Dispose DataContext if it implements IDisposable when window closes
        /// </summary>
        private void OnWindowClosed(object? sender, EventArgs e)
        {
            if (DataContext is IDisposable disposable)
            {
                disposable.Dispose();
            }
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
                    Width = 1000;
                    Height = 700;
                }
            }
        }

        protected virtual void OnKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                Close();
                e.Handled = true;
            }
        }

        protected void OnCloseClick(object? sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
