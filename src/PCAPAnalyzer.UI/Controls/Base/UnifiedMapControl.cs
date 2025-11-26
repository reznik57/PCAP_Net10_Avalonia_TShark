using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Threading;

namespace PCAPAnalyzer.UI.Controls.Base
{
    /// <summary>
    /// Unified base class for all map controls.
    /// Provides common infrastructure for rendering, animation, and interaction.
    /// Uses composition for flexibility - specific map behaviors are injected via strategies.
    /// </summary>
    public abstract class UnifiedMapControl : Control
    {
        #region Fields

        private readonly DispatcherTimer _animationTimer;
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI particle effects and animation jitter, not security
        private readonly Random _random = new();
#pragma warning restore CA5394
        private readonly List<MapParticle> _particles = new();

        protected DispatcherTimer AnimationTimer => _animationTimer;
        protected Random Random => _random;
        protected List<MapParticle> Particles => _particles;

        protected double AnimationPhase { get; set; }
        protected Point PanOffset { get; set; } = new(0, 0);
        protected double ZoomLevel { get; set; } = 1.0;
        protected string? HoveredCountry { get; set; }
        protected Point? LastMousePosition { get; set; }
        protected bool IsPanning { get; set; }

        #endregion

        #region Styled Properties

        /// <summary>
        /// Traffic data by country code
        /// </summary>
        public static readonly StyledProperty<Dictionary<string, double>?> CountryDataProperty =
            AvaloniaProperty.Register<UnifiedMapControl, Dictionary<string, double>?>(nameof(CountryData));

        /// <summary>
        /// Countries to exclude from visualization
        /// </summary>
        public static readonly StyledProperty<ObservableCollection<string>> ExcludedCountriesProperty =
            AvaloniaProperty.Register<UnifiedMapControl, ObservableCollection<string>>(
                nameof(ExcludedCountries), new ObservableCollection<string>());

        /// <summary>
        /// Enable/disable animations
        /// </summary>
        public static readonly StyledProperty<bool> ShowAnimationsProperty =
            AvaloniaProperty.Register<UnifiedMapControl, bool>(nameof(ShowAnimations), true);

        /// <summary>
        /// Show/hide particle effects
        /// </summary>
        public static readonly StyledProperty<bool> ShowParticlesProperty =
            AvaloniaProperty.Register<UnifiedMapControl, bool>(nameof(ShowParticles), true);

        /// <summary>
        /// Show/hide grid lines
        /// </summary>
        public static readonly StyledProperty<bool> ShowGridLinesProperty =
            AvaloniaProperty.Register<UnifiedMapControl, bool>(nameof(ShowGridLines), true);

        /// <summary>
        /// Show/hide traffic flow animations
        /// </summary>
        public static readonly StyledProperty<bool> ShowTrafficFlowsProperty =
            AvaloniaProperty.Register<UnifiedMapControl, bool>(nameof(ShowTrafficFlows), true);

        /// <summary>
        /// Show/hide country labels
        /// </summary>
        public static readonly StyledProperty<bool> ShowCountryLabelsProperty =
            AvaloniaProperty.Register<UnifiedMapControl, bool>(nameof(ShowCountryLabels), true);

        /// <summary>
        /// Animation frame rate in FPS
        /// </summary>
        public static readonly StyledProperty<int> FrameRateProperty =
            AvaloniaProperty.Register<UnifiedMapControl, int>(nameof(FrameRate), 60);

        #endregion

        #region Public Properties

        public Dictionary<string, double>? CountryData
        {
            get => GetValue(CountryDataProperty);
            set => SetValue(CountryDataProperty, value);
        }

        public ObservableCollection<string> ExcludedCountries
        {
            get => GetValue(ExcludedCountriesProperty);
            set => SetValue(ExcludedCountriesProperty, value);
        }

        public bool ShowAnimations
        {
            get => GetValue(ShowAnimationsProperty);
            set => SetValue(ShowAnimationsProperty, value);
        }

        public bool ShowParticles
        {
            get => GetValue(ShowParticlesProperty);
            set => SetValue(ShowParticlesProperty, value);
        }

        public bool ShowGridLines
        {
            get => GetValue(ShowGridLinesProperty);
            set => SetValue(ShowGridLinesProperty, value);
        }

        public bool ShowTrafficFlows
        {
            get => GetValue(ShowTrafficFlowsProperty);
            set => SetValue(ShowTrafficFlowsProperty, value);
        }

        public bool ShowCountryLabels
        {
            get => GetValue(ShowCountryLabelsProperty);
            set => SetValue(ShowCountryLabelsProperty, value);
        }

        public int FrameRate
        {
            get => GetValue(FrameRateProperty);
            set => SetValue(FrameRateProperty, value);
        }

        #endregion

        #region Constructor

        static UnifiedMapControl()
        {
            AffectsRender<UnifiedMapControl>(
                CountryDataProperty,
                ExcludedCountriesProperty,
                ShowAnimationsProperty,
                ShowParticlesProperty,
                ShowGridLinesProperty,
                ShowTrafficFlowsProperty,
                ShowCountryLabelsProperty);
        }

        protected UnifiedMapControl()
        {
            // Setup animation timer
            _animationTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(1000.0 / FrameRate)
            };
            _animationTimer.Tick += OnAnimationTick;

            // Start animation if enabled
            if (ShowAnimations)
            {
                AnimationTimer.Start();
            }

            // Subscribe to property changes
            ShowAnimationsProperty.Changed.AddClassHandler<UnifiedMapControl>(OnShowAnimationsChanged);
            FrameRateProperty.Changed.AddClassHandler<UnifiedMapControl>(OnFrameRateChanged);
        }

        #endregion

        #region Abstract Methods

        /// <summary>
        /// Render the map. Override in derived classes to implement specific visualization.
        /// </summary>
        protected abstract void RenderMap(DrawingContext context, Rect bounds);

        /// <summary>
        /// Update animation state. Override to implement custom animations.
        /// </summary>
        protected abstract void UpdateAnimations();

        /// <summary>
        /// Handle country click event. Override to implement custom behavior.
        /// </summary>
        protected abstract void OnCountryClicked(string countryCode);

        #endregion

        #region Rendering

        public sealed override void Render(DrawingContext context)
        {
            base.Render(context);

            var bounds = new Rect(0, 0, Bounds.Width, Bounds.Height);
            if (bounds.Width <= 0 || bounds.Height <= 0)
                return;

            // Render background
            context.FillRectangle(Brushes.Transparent, bounds);

            // Apply transformations (zoom and pan)
            using (context.PushTransform(CreateTransformMatrix()))
            {
                // Render grid lines if enabled
                if (ShowGridLines)
                {
                    RenderGridLines(context, bounds);
                }

                // Render the map (implemented by derived classes)
                RenderMap(context, bounds);

                // Render particles if enabled
                if (ShowParticles && ShowAnimations)
                {
                    RenderParticles(context);
                }
            }
        }

        private Matrix CreateTransformMatrix()
        {
            return Matrix.CreateScale(ZoomLevel, ZoomLevel) *
                   Matrix.CreateTranslation(PanOffset.X, PanOffset.Y);
        }

        protected virtual void RenderGridLines(DrawingContext context, Rect bounds)
        {
            var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(32, 255, 255, 255)), 1);

            // Vertical lines (longitude)
            for (int i = 0; i <= 12; i++)
            {
                double x = bounds.Width * i / 12.0;
                context.DrawLine(gridPen, new Point(x, 0), new Point(x, bounds.Height));
            }

            // Horizontal lines (latitude)
            for (int i = 0; i <= 6; i++)
            {
                double y = bounds.Height * i / 6.0;
                context.DrawLine(gridPen, new Point(0, y), new Point(bounds.Width, y));
            }
        }

        protected virtual void RenderParticles(DrawingContext context)
        {
            foreach (var particle in Particles)
            {
                if (!particle.IsActive) continue;

                var color = Color.FromArgb(
                    (byte)(particle.Opacity * 255),
                    particle.Color.R,
                    particle.Color.G,
                    particle.Color.B);

                var brush = new SolidColorBrush(color);
                var rect = new Rect(particle.X - particle.Size / 2, particle.Y - particle.Size / 2,
                    particle.Size, particle.Size);

                context.FillRectangle(brush, rect);
            }
        }

        #endregion

        #region Animation

        private void OnAnimationTick(object? sender, EventArgs e)
        {
            if (!ShowAnimations) return;

            AnimationPhase = (AnimationPhase + 0.05) % (Math.PI * 2);

            // Update particles
            UpdateParticles();

            // Call derived class animation update
            UpdateAnimations();

            // Trigger render
            InvalidateVisual();
        }

        protected virtual void UpdateParticles()
        {
            for (int i = Particles.Count - 1; i >= 0; i--)
            {
                var particle = Particles[i];
                particle.Update();

                if (!particle.IsActive)
                {
                    Particles.RemoveAt(i);
                }
            }
        }

        protected void SpawnParticle(double x, double y, Color color, double velocityX = 0, double velocityY = 0)
        {
#pragma warning disable CA5394 // Random used only for UI particle size variation, not security
            Particles.Add(new MapParticle
            {
                X = x,
                Y = y,
                Color = color,
                VelocityX = velocityX,
                VelocityY = velocityY,
                Life = 1.0,
                Size = Random.NextDouble() * 3 + 1
            });
#pragma warning restore CA5394
        }

        #endregion

        #region Interaction

        protected override void OnPointerPressed(PointerPressedEventArgs e)
        {
            base.OnPointerPressed(e);

            var point = e.GetPosition(this);
            LastMousePosition = point;

            if (e.GetCurrentPoint(this).Properties.IsMiddleButtonPressed ||
                e.GetCurrentPoint(this).Properties.IsRightButtonPressed)
            {
                IsPanning = true;
                e.Handled = true;
            }
        }

        protected override void OnPointerMoved(PointerEventArgs e)
        {
            base.OnPointerMoved(e);

            var currentPos = e.GetPosition(this);

            if (IsPanning && LastMousePosition.HasValue)
            {
                var delta = currentPos - LastMousePosition.Value;
                PanOffset = new Point(PanOffset.X + delta.X, PanOffset.Y + delta.Y);
                InvalidateVisual();
            }

            LastMousePosition = currentPos;

            // Update hovered country (derived classes can override)
            UpdateHoveredCountry(currentPos);
        }

        protected override void OnPointerReleased(PointerReleasedEventArgs e)
        {
            base.OnPointerReleased(e);
            IsPanning = false;
        }

        protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
        {
            base.OnPointerWheelChanged(e);

            var delta = e.Delta.Y;
            var oldZoom = ZoomLevel;
            ZoomLevel = Math.Clamp(ZoomLevel + delta * 0.1, 0.5, 5.0);

            // Adjust pan to zoom toward cursor
            var mousePos = e.GetPosition(this);
            var zoomFactor = ZoomLevel / oldZoom;
            PanOffset = new Point(
                mousePos.X - (mousePos.X - PanOffset.X) * zoomFactor,
                mousePos.Y - (mousePos.Y - PanOffset.Y) * zoomFactor
            );

            InvalidateVisual();
            e.Handled = true;
        }

        protected virtual void UpdateHoveredCountry(Point mousePosition)
        {
            // Override in derived classes to implement country hit testing
        }

        #endregion

        #region Property Change Handlers

        private static void OnShowAnimationsChanged(UnifiedMapControl control, AvaloniaPropertyChangedEventArgs e)
        {
            if ((bool)e.NewValue!)
            {
                control.AnimationTimer.Start();
            }
            else
            {
                control.AnimationTimer.Stop();
            }
        }

        private static void OnFrameRateChanged(UnifiedMapControl control, AvaloniaPropertyChangedEventArgs e)
        {
            var fps = (int)e.NewValue!;
            control.AnimationTimer.Interval = TimeSpan.FromMilliseconds(1000.0 / fps);
        }

        #endregion

        #region Helper Classes

        protected class MapParticle
        {
            public double X { get; set; }
            public double Y { get; set; }
            public double VelocityX { get; set; }
            public double VelocityY { get; set; }
            public Color Color { get; set; }
            public double Size { get; set; }
            public double Life { get; set; }
            public double Opacity => Life;
            public bool IsActive => Life > 0;

            public void Update()
            {
                X += VelocityX;
                Y += VelocityY;
                Life -= 0.02;
                VelocityY += 0.1; // Gravity
            }
        }

        #endregion
    }
}
