using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.Media;

namespace PCAPAnalyzer.UI.Controls
{
    public partial class ResizablePopupView : UserControl
    {
        private Border? _resizableBorder;
        private Border? _headerBorder;
        private Button? _maximizeButton;
        private TextBlock? _sizeIndicator;
        private Grid? _popupContainer;
        
        private bool _isResizing;
        private bool _isDragging;
        private bool _isMaximized;
        private Point _startPoint;
        private Size _startSize;
        private Point _startPosition;
        private string _resizeDirection = "";
        
        // Store original size and position for restore
        private double _originalWidth = 1000;
        private double _originalHeight = 650;
        private double _originalLeft;
        private double _originalTop;
        
        public ResizablePopupView()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }

        protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
        {
            base.OnAttachedToVisualTree(e);
            
            // Get references to controls
            _resizableBorder = this.FindControl<Border>("ResizableBorder");
            _headerBorder = this.FindControl<Border>("HeaderBorder");
            _maximizeButton = this.FindControl<Button>("MaximizeButton");
            _sizeIndicator = this.FindControl<TextBlock>("SizeIndicator");
            _popupContainer = this.FindControl<Grid>("PopupContainer");
            
            if (_resizableBorder is not null && _sizeIndicator is not null)
            {
                UpdateSizeIndicator();
                
                // Watch for size changes
                _resizableBorder.PropertyChanged += (s, args) =>
                {
                    if (args.Property == WidthProperty || args.Property == HeightProperty)
                    {
                        UpdateSizeIndicator();
                    }
                };
            }
            
            // Setup header drag
            if (_headerBorder is not null)
            {
                _headerBorder.PointerPressed += OnHeaderPointerPressed;
                _headerBorder.PointerMoved += OnHeaderPointerMoved;
                _headerBorder.PointerReleased += OnHeaderPointerReleased;
            }
            
            // Setup maximize button
            if (_maximizeButton is not null)
            {
                _maximizeButton.Click += OnMaximizeClick;
            }
            
            // Setup resize handles
            SetupResizeHandle("ResizeNW", "nw");
            SetupResizeHandle("ResizeN", "n");
            SetupResizeHandle("ResizeNE", "ne");
            SetupResizeHandle("ResizeW", "w");
            SetupResizeHandle("ResizeE", "e");
            SetupResizeHandle("ResizeSW", "sw");
            SetupResizeHandle("ResizeS", "s");
            SetupResizeHandle("ResizeSE", "se");
        }
        
        private void SetupResizeHandle(string name, string direction)
        {
            var handle = this.FindControl<Border>(name);
            if (handle is not null)
            {
                handle.PointerPressed += (s, e) => OnResizeStart(s, e, direction);
                handle.PointerMoved += OnResizeMove;
                handle.PointerReleased += OnResizeEnd;
            }
        }
        
        private void OnResizeStart(object? sender, PointerPressedEventArgs e, string direction)
        {
            if (_resizableBorder is null || _isMaximized) return;
            
            _isResizing = true;
            _resizeDirection = direction;
            _startPoint = e.GetPosition(this);
            _startSize = new Size(_resizableBorder.Width, _resizableBorder.Height);
            
            if (_popupContainer is not null)
            {
                var transform = _popupContainer.RenderTransform as TranslateTransform;
                if (transform is not null)
                {
                    _startPosition = new Point(transform.X, transform.Y);
                }
                else
                {
                    _startPosition = new Point(0, 0);
                }
            }
            
            if (sender is IInputElement element)
            {
                e.Pointer.Capture(element);
            }
            e.Handled = true;
        }
        
        private void OnResizeMove(object? sender, PointerEventArgs e)
        {
            if (!_isResizing || _resizableBorder is null || _popupContainer is null) return;
            
            var currentPoint = e.GetPosition(this);
            var deltaX = currentPoint.X - _startPoint.X;
            var deltaY = currentPoint.Y - _startPoint.Y;
            
            double newWidth = _startSize.Width;
            double newHeight = _startSize.Height;
            double newX = _startPosition.X;
            double newY = _startPosition.Y;
            
            // Calculate new size based on resize direction
            switch (_resizeDirection)
            {
                case "n":
                    newHeight = Math.Max(_resizableBorder.MinHeight, _startSize.Height - deltaY);
                    newY = _startPosition.Y + (_startSize.Height - newHeight);
                    break;
                case "s":
                    newHeight = Math.Max(_resizableBorder.MinHeight, _startSize.Height + deltaY);
                    break;
                case "w":
                    newWidth = Math.Max(_resizableBorder.MinWidth, _startSize.Width - deltaX);
                    newX = _startPosition.X + (_startSize.Width - newWidth);
                    break;
                case "e":
                    newWidth = Math.Max(_resizableBorder.MinWidth, _startSize.Width + deltaX);
                    break;
                case "nw":
                    newWidth = Math.Max(_resizableBorder.MinWidth, _startSize.Width - deltaX);
                    newHeight = Math.Max(_resizableBorder.MinHeight, _startSize.Height - deltaY);
                    newX = _startPosition.X + (_startSize.Width - newWidth);
                    newY = _startPosition.Y + (_startSize.Height - newHeight);
                    break;
                case "ne":
                    newWidth = Math.Max(_resizableBorder.MinWidth, _startSize.Width + deltaX);
                    newHeight = Math.Max(_resizableBorder.MinHeight, _startSize.Height - deltaY);
                    newY = _startPosition.Y + (_startSize.Height - newHeight);
                    break;
                case "sw":
                    newWidth = Math.Max(_resizableBorder.MinWidth, _startSize.Width - deltaX);
                    newHeight = Math.Max(_resizableBorder.MinHeight, _startSize.Height + deltaY);
                    newX = _startPosition.X + (_startSize.Width - newWidth);
                    break;
                case "se":
                    newWidth = Math.Max(_resizableBorder.MinWidth, _startSize.Width + deltaX);
                    newHeight = Math.Max(_resizableBorder.MinHeight, _startSize.Height + deltaY);
                    break;
            }
            
            // Apply size constraints
            newWidth = Math.Min(Math.Max(newWidth, _resizableBorder.MinWidth), _resizableBorder.MaxWidth);
            newHeight = Math.Min(Math.Max(newHeight, _resizableBorder.MinHeight), _resizableBorder.MaxHeight);
            
            // Apply new size
            _resizableBorder.Width = newWidth;
            _resizableBorder.Height = newHeight;
            
            // Apply new position if needed (for corner and edge resizing)
            if (_resizeDirection.Contains("n", StringComparison.Ordinal) || _resizeDirection.Contains("w", StringComparison.Ordinal))
            {
                _popupContainer.RenderTransform = new TranslateTransform(newX, newY);
            }
            
            UpdateSizeIndicator();
            e.Handled = true;
        }
        
        private void OnResizeEnd(object? sender, PointerReleasedEventArgs e)
        {
            if (!_isResizing) return;
            
            _isResizing = false;
            _resizeDirection = "";
            e.Pointer.Capture(null);
            e.Handled = true;
        }
        
        private void OnHeaderPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            if (_isMaximized) return;
            
            // Check for double-click to maximize
            if (e.ClickCount == 2)
            {
                ToggleMaximize();
                e.Handled = true;
                return;
            }
            
            _isDragging = true;
            _startPoint = e.GetPosition(this);
            
            if (_popupContainer is not null)
            {
                var transform = _popupContainer.RenderTransform as TranslateTransform;
                if (transform is not null)
                {
                    _startPosition = new Point(transform.X, transform.Y);
                }
                else
                {
                    _startPosition = new Point(0, 0);
                }
            }
            
            e.Pointer.Capture((IInputElement)sender!);
            e.Handled = true;
        }
        
        private void OnHeaderPointerMoved(object? sender, PointerEventArgs e)
        {
            if (!_isDragging || _popupContainer is null) return;
            
            var currentPoint = e.GetPosition(this);
            var offsetX = currentPoint.X - _startPoint.X;
            var offsetY = currentPoint.Y - _startPoint.Y;
            
            var newX = _startPosition.X + offsetX;
            var newY = _startPosition.Y + offsetY;
            
            _popupContainer.RenderTransform = new TranslateTransform(newX, newY);
            e.Handled = true;
        }
        
        private void OnHeaderPointerReleased(object? sender, PointerReleasedEventArgs e)
        {
            if (!_isDragging) return;
            
            _isDragging = false;
            e.Pointer.Capture(null);
            e.Handled = true;
        }
        
        private void OnMaximizeClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            ToggleMaximize();
        }
        
        private void ToggleMaximize()
        {
            if (_resizableBorder is null || _popupContainer is null || _maximizeButton is null) return;
            
            if (_isMaximized)
            {
                // Restore to original size
                _resizableBorder.Width = _originalWidth;
                _resizableBorder.Height = _originalHeight;
                _popupContainer.RenderTransform = new TranslateTransform(_originalLeft, _originalTop);
                
                // Update maximize button icon
                var path = _maximizeButton.Content as Avalonia.Controls.Shapes.Path;
                if (path is not null)
                {
                    path.Data = Geometry.Parse("M 4 4 L 20 4 L 20 20 L 4 20 Z M 4 7 L 20 7");
                }
                
                ToolTip.SetTip(_maximizeButton, "Maximize");
                _isMaximized = false;
            }
            else
            {
                // Store current size and position
                _originalWidth = _resizableBorder.Width;
                _originalHeight = _resizableBorder.Height;
                
                var transform = _popupContainer.RenderTransform as TranslateTransform;
                if (transform is not null)
                {
                    _originalLeft = transform.X;
                    _originalTop = transform.Y;
                }
                else
                {
                    _originalLeft = 0;
                    _originalTop = 0;
                }
                
                // Maximize (use parent bounds)
                if (Parent is Control parent)
                {
                    _resizableBorder.Width = Math.Min(parent.Bounds.Width * 0.95, _resizableBorder.MaxWidth);
                    _resizableBorder.Height = Math.Min(parent.Bounds.Height * 0.95, _resizableBorder.MaxHeight);
                }
                else
                {
                    _resizableBorder.Width = _resizableBorder.MaxWidth;
                    _resizableBorder.Height = _resizableBorder.MaxHeight;
                }
                
                _popupContainer.RenderTransform = new TranslateTransform(0, 0);
                
                // Update maximize button icon (restore icon)
                var path = _maximizeButton.Content as Avalonia.Controls.Shapes.Path;
                if (path is not null)
                {
                    path.Data = Geometry.Parse("M 4 8 L 8 8 L 8 4 L 20 4 L 20 16 L 16 16 M 4 12 L 4 20 L 16 20 L 16 12 Z");
                }
                
                ToolTip.SetTip(_maximizeButton, "Restore");
                _isMaximized = true;
            }
            
            UpdateSizeIndicator();
        }
        
        private void UpdateSizeIndicator()
        {
            if (_sizeIndicator is not null && _resizableBorder is not null)
            {
                _sizeIndicator.Text = $"{_resizableBorder.Width:F0} × {_resizableBorder.Height:F0}";
            }
        }
    }
}