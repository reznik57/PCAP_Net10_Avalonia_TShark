using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Threading;

namespace PCAPAnalyzer.UI.Controls
{
    public class ContinentSubmapControl : Control
    {
        private readonly string _continentName;
        private readonly Dictionary<string, CountryInfo> _countries = new();
        private readonly List<TrafficFlow> _trafficFlows = new();
        private readonly DispatcherTimer _animationTimer;
        private double _animationPhase;
        private Point? _hoveredPoint;
        private string? _hoveredCountry;
        private double _zoomLevel = 1.0;
        private Point _panOffset = new(0, 0);
        private bool _isPanning;
        private Point _lastPanPoint;

        // Styled Properties
        public static readonly StyledProperty<Dictionary<string, double>?> CountryDataProperty =
            AvaloniaProperty.Register<ContinentSubmapControl, Dictionary<string, double>?>(nameof(CountryData));

        public static readonly StyledProperty<bool> ShowAnimationsProperty =
            AvaloniaProperty.Register<ContinentSubmapControl, bool>(nameof(ShowAnimations), true);

        public static readonly StyledProperty<bool> ShowLabelsProperty =
            AvaloniaProperty.Register<ContinentSubmapControl, bool>(nameof(ShowLabels), true);

        public Dictionary<string, double>? CountryData
        {
            get => GetValue(CountryDataProperty);
            set => SetValue(CountryDataProperty, value);
        }

        public bool ShowAnimations
        {
            get => GetValue(ShowAnimationsProperty);
            set => SetValue(ShowAnimationsProperty, value);
        }

        public bool ShowLabels
        {
            get => GetValue(ShowLabelsProperty);
            set => SetValue(ShowLabelsProperty, value);
        }

        public ContinentSubmapControl(string continentName)
        {
            _continentName = continentName;
            InitializeCountries();
            
            _animationTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(16) // 60 FPS
            };
            _animationTimer.Tick += OnAnimationTick;
            _animationTimer.Start();

            // Setup interaction handlers
            PointerMoved += OnPointerMoved;
            PointerPressed += OnPointerPressed;
            PointerReleased += OnPointerReleased;
            PointerWheelChanged += OnPointerWheelChanged;
            DoubleTapped += OnDoubleTapped;
        }

        private void InitializeCountries()
        {
            // Initialize countries based on continent
            var countriesByContinent = GetCountriesByContinent(_continentName);
            
            int gridCols = (int)Math.Ceiling(Math.Sqrt(countriesByContinent.Count));
            int gridRows = (int)Math.Ceiling((double)countriesByContinent.Count / gridCols);
            
            int index = 0;
            foreach (var country in countriesByContinent)
            {
                int row = index / gridCols;
                int col = index % gridCols;
                
                _countries[country.Code] = new CountryInfo
                {
                    Code = country.Code,
                    Name = country.Name,
                    GridPosition = new Point(col * 120 + 60, row * 100 + 50),
                    Color = GetCountryColor(country.Code)
                };
                index++;
            }
        }

        private List<(string Code, string Name)> GetCountriesByContinent(string continent)
        {
            return continent switch
            {
                "North America" => new List<(string, string)>
                {
                    ("US", "United States"), ("CA", "Canada"), ("MX", "Mexico"),
                    ("GT", "Guatemala"), ("CU", "Cuba"), ("HT", "Haiti"),
                    ("DO", "Dominican Republic"), ("HN", "Honduras"), ("NI", "Nicaragua"),
                    ("CR", "Costa Rica"), ("PA", "Panama"), ("JM", "Jamaica"),
                    ("TT", "Trinidad and Tobago"), ("BB", "Barbados"), ("BS", "Bahamas"),
                    ("BZ", "Belize"), ("SV", "El Salvador")
                },
                "South America" => new List<(string, string)>
                {
                    ("BR", "Brazil"), ("AR", "Argentina"), ("CL", "Chile"),
                    ("CO", "Colombia"), ("PE", "Peru"), ("VE", "Venezuela"),
                    ("EC", "Ecuador"), ("BO", "Bolivia"), ("PY", "Paraguay"),
                    ("UY", "Uruguay"), ("GY", "Guyana"), ("SR", "Suriname"),
                    ("GF", "French Guiana")
                },
                "Europe" => new List<(string, string)>
                {
                    ("GB", "United Kingdom"), ("DE", "Germany"), ("FR", "France"),
                    ("IT", "Italy"), ("ES", "Spain"), ("NL", "Netherlands"),
                    ("BE", "Belgium"), ("CH", "Switzerland"), ("AT", "Austria"),
                    ("SE", "Sweden"), ("NO", "Norway"), ("DK", "Denmark"),
                    ("FI", "Finland"), ("PL", "Poland"), ("PT", "Portugal"),
                    ("GR", "Greece"), ("CZ", "Czech Republic"), ("HU", "Hungary"),
                    ("RO", "Romania"), ("BG", "Bulgaria"), ("HR", "Croatia"),
                    ("RS", "Serbia"), ("SK", "Slovakia"), ("SI", "Slovenia"),
                    ("UA", "Ukraine"), ("BY", "Belarus"), ("MD", "Moldova"),
                    ("LT", "Lithuania"), ("LV", "Latvia"), ("EE", "Estonia"),
                    ("IE", "Ireland"), ("IS", "Iceland"), ("LU", "Luxembourg"),
                    ("MT", "Malta"), ("CY", "Cyprus"), ("AL", "Albania"),
                    ("MK", "North Macedonia"), ("BA", "Bosnia"), ("ME", "Montenegro"),
                    ("XK", "Kosovo"), ("RU", "Russia")
                },
                "Africa" => new List<(string, string)>
                {
                    ("ZA", "South Africa"), ("EG", "Egypt"), ("NG", "Nigeria"),
                    ("KE", "Kenya"), ("MA", "Morocco"), ("ET", "Ethiopia"),
                    ("GH", "Ghana"), ("AO", "Angola"), ("TZ", "Tanzania"),
                    ("DZ", "Algeria"), ("SD", "Sudan"), ("UG", "Uganda"),
                    ("MZ", "Mozambique"), ("MG", "Madagascar"), ("CM", "Cameroon"),
                    ("CI", "Ivory Coast"), ("NE", "Niger"), ("BF", "Burkina Faso"),
                    ("ML", "Mali"), ("MW", "Malawi"), ("ZM", "Zambia"),
                    ("SN", "Senegal"), ("SO", "Somalia"), ("TD", "Chad"),
                    ("ZW", "Zimbabwe"), ("GN", "Guinea"), ("RW", "Rwanda"),
                    ("BJ", "Benin"), ("TN", "Tunisia"), ("BI", "Burundi"),
                    ("TG", "Togo"), ("SL", "Sierra Leone"), ("LY", "Libya"),
                    ("LR", "Liberia"), ("MR", "Mauritania"), ("CF", "Central African Republic"),
                    ("ER", "Eritrea"), ("GM", "Gambia"), ("GA", "Gabon"),
                    ("BW", "Botswana"), ("LS", "Lesotho"), ("NA", "Namibia"),
                    ("GQ", "Equatorial Guinea"), ("SZ", "Eswatini"), ("DJ", "Djibouti"),
                    ("KM", "Comoros"), ("CV", "Cape Verde"), ("SC", "Seychelles"),
                    ("ST", "Sao Tome"), ("MU", "Mauritius")
                },
                "Asia" => new List<(string, string)>
                {
                    ("CN", "China"), ("JP", "Japan"), ("IN", "India"),
                    ("KR", "South Korea"), ("SG", "Singapore"), ("HK", "Hong Kong"),
                    ("TW", "Taiwan"), ("TH", "Thailand"), ("MY", "Malaysia"),
                    ("ID", "Indonesia"), ("PH", "Philippines"), ("VN", "Vietnam"),
                    ("PK", "Pakistan"), ("BD", "Bangladesh"), ("TR", "Turkey"),
                    ("IR", "Iran"), ("IQ", "Iraq"), ("SA", "Saudi Arabia"),
                    ("YE", "Yemen"), ("SY", "Syria"), ("JO", "Jordan"),
                    ("AE", "UAE"), ("IL", "Israel"), ("LB", "Lebanon"),
                    ("OM", "Oman"), ("KW", "Kuwait"), ("QA", "Qatar"),
                    ("BH", "Bahrain"), ("KZ", "Kazakhstan"), ("UZ", "Uzbekistan"),
                    ("TM", "Turkmenistan"), ("AF", "Afghanistan"), ("TJ", "Tajikistan"),
                    ("KG", "Kyrgyzstan"), ("AZ", "Azerbaijan"), ("AM", "Armenia"),
                    ("GE", "Georgia"), ("MN", "Mongolia"), ("KP", "North Korea"),
                    ("LA", "Laos"), ("MM", "Myanmar"), ("KH", "Cambodia"),
                    ("BN", "Brunei"), ("TL", "Timor-Leste"), ("MV", "Maldives"),
                    ("BT", "Bhutan"), ("LK", "Sri Lanka"), ("NP", "Nepal")
                },
                "Oceania" => new List<(string, string)>
                {
                    ("AU", "Australia"), ("NZ", "New Zealand"), ("PG", "Papua New Guinea"),
                    ("FJ", "Fiji"), ("SB", "Solomon Islands"), ("NC", "New Caledonia"),
                    ("PF", "French Polynesia"), ("VU", "Vanuatu"), ("WS", "Samoa"),
                    ("KI", "Kiribati"), ("TO", "Tonga"), ("FM", "Micronesia"),
                    ("PW", "Palau"), ("MH", "Marshall Islands"), ("NR", "Nauru"),
                    ("TV", "Tuvalu"), ("CK", "Cook Islands"), ("NU", "Niue"),
                    ("TK", "Tokelau"), ("GU", "Guam"), ("MP", "Northern Mariana Islands"),
                    ("AS", "American Samoa")
                },
                _ => new List<(string, string)>()
            };
        }

        private Color GetCountryColor(string countryCode)
        {
            // Generate a color based on country code
            var hash = Math.Abs(countryCode.GetHashCode(StringComparison.Ordinal));
            var r = (byte)((hash & 0xFF0000) >> 16);
            var g = (byte)((hash & 0x00FF00) >> 8);
            var b = (byte)(hash & 0x0000FF);
            
            // Ensure minimum brightness
            if (r < 100 && g < 100 && b < 100)
            {
                r = (byte)Math.Min(r + 100, 255);
                g = (byte)Math.Min(g + 100, 255);
                b = (byte)Math.Min(b + 100, 255);
            }
            
            return Color.FromRgb(r, g, b);
        }

        private void OnAnimationTick(object? sender, EventArgs e)
        {
            if (!ShowAnimations) return;
            
            _animationPhase += 0.02;
            
            // Update traffic flows
            foreach (var flow in _trafficFlows.ToList())
            {
                flow.Progress += 0.02;
                if (flow.Progress > 1.0)
                {
                    _trafficFlows.Remove(flow);
                }
            }
            
            // Create new flows occasionally
#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI animation timing, not security
            if (CountryData != null && _trafficFlows.Count < 5 && new Random().NextDouble() < 0.05)
#pragma warning restore CA5394
            {
                CreateRandomTrafficFlow();
            }
            
            InvalidateVisual();
        }

        private void CreateRandomTrafficFlow()
        {
            if (CountryData == null || CountryData.Count < 2) return;

#pragma warning disable CA5394 // Do not use insecure randomness - Used only for UI visualization randomness, not security
            var random = new Random();
            var countries = CountryData.Keys.ToList();
            var source = countries[random.Next(countries.Count)];
            var dest = countries[random.Next(countries.Count)];
#pragma warning restore CA5394
            
            if (source != dest && _countries.ContainsKey(source) && _countries.ContainsKey(dest))
            {
                _trafficFlows.Add(new TrafficFlow
                {
                    SourceCountry = source,
                    DestinationCountry = dest,
                    Progress = 0,
                    Color = Color.FromArgb(180, 47, 129, 247) // Semi-transparent blue
                });
            }
        }

        public override void Render(DrawingContext context)
        {
            base.Render(context);
            
            // Atmospheric background for submap view
            var background = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                GradientStops = new GradientStops
                {
                    new GradientStop { Color = Color.FromRgb(6, 10, 18), Offset = 0 },
                    new GradientStop { Color = Color.FromRgb(11, 20, 36), Offset = 0.5 },
                    new GradientStop { Color = Color.FromRgb(3, 6, 12), Offset = 1 }
                }
            };
            context.FillRectangle(background, new Rect(Bounds.Size));

            var focusGlow = new RadialGradientBrush
            {
                Center = new RelativePoint(0.35, 0.3, RelativeUnit.Relative),
                GradientStops = new GradientStops
                {
                    new GradientStop { Color = Color.FromArgb(70, 63, 131, 248), Offset = 0 },
                    new GradientStop { Color = Color.FromArgb(0, 63, 131, 248), Offset = 1 }
                }
            };
            context.DrawEllipse(focusGlow, null, new Point(Bounds.Width * 0.45, Bounds.Height * 0.35), Bounds.Width * 0.35, Bounds.Height * 0.3);
            
            // Apply transforms
            using (context.PushTransform(Matrix.CreateTranslation(_panOffset.X, _panOffset.Y) * 
                                        Matrix.CreateScale(_zoomLevel, _zoomLevel)))
            {
                // Draw grid
                DrawGrid(context);
                
                // Draw traffic flows
                DrawTrafficFlows(context);
                
                // Draw countries
                DrawCountries(context);
                
                // Draw labels
                if (ShowLabels)
                {
                    DrawLabels(context);
                }
            }
            
            // Draw overlay UI
            DrawOverlay(context);
            
            // Draw tooltip
            if (_hoveredCountry != null && _hoveredPoint.HasValue)
            {
                DrawTooltip(context, _hoveredPoint.Value, _hoveredCountry);
            }
        }

        private void DrawGrid(DrawingContext context)
        {
            var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(28, 148, 163, 184)), 1);
            var spacing = 60;

            for (int x = -spacing * 2; x < Bounds.Width * 2; x += spacing)
            {
                context.DrawLine(gridPen, new Point(x, -spacing * 2), new Point(x, Bounds.Height * 2));
            }

            for (int y = -spacing * 2; y < Bounds.Height * 2; y += spacing)
            {
                context.DrawLine(gridPen, new Point(-spacing * 2, y), new Point(Bounds.Width * 2, y));
            }
        }

        private void DrawTrafficFlows(DrawingContext context)
        {
            foreach (var flow in _trafficFlows)
            {
                if (!_countries.ContainsKey(flow.SourceCountry) || 
                    !_countries.ContainsKey(flow.DestinationCountry))
                    continue;
                
                var source = _countries[flow.SourceCountry].GridPosition;
                var dest = _countries[flow.DestinationCountry].GridPosition;
                
                // Calculate current position along path
                var currentX = source.X + (dest.X - source.X) * flow.Progress;
                var currentY = source.Y + (dest.Y - source.Y) * flow.Progress;
                
                // Draw trail
                var trailOpacity = (byte)(100 * (1 - flow.Progress));
                var trailBrush = new LinearGradientBrush
                {
                    StartPoint = new RelativePoint(source.X, source.Y, RelativeUnit.Absolute),
                    EndPoint = new RelativePoint(currentX, currentY, RelativeUnit.Absolute),
                    GradientStops = new GradientStops
                    {
                        new GradientStop { Color = Color.FromArgb(trailOpacity, flow.Color.R, flow.Color.G, flow.Color.B), Offset = 0 },
                        new GradientStop { Color = Color.FromArgb(0, flow.Color.R, flow.Color.G, flow.Color.B), Offset = 1 }
                    }
                };
                context.DrawLine(new Pen(trailBrush, 2), source, new Point(currentX, currentY));
                
                // Draw packet
                var packetBrush = new RadialGradientBrush
                {
                    Center = new RelativePoint(0.5, 0.5, RelativeUnit.Relative),
                    GradientStops = new GradientStops
                    {
                        new GradientStop { Color = flow.Color, Offset = 0 },
                        new GradientStop { Color = Color.FromArgb(0, flow.Color.R, flow.Color.G, flow.Color.B), Offset = 1 }
                    }
                };
                context.DrawEllipse(packetBrush, null, new Point(currentX, currentY), 5, 5);
            }
        }

        private void DrawCountries(DrawingContext context)
        {
            foreach (var country in _countries.Values)
            {
                var trafficValue = CountryData?.GetValueOrDefault(country.Code, 0) ?? 0;
                var radius = 20 + trafficValue * 0.3;

                var baseAlpha = ClampToByte(90 + trafficValue * 1.8);
                var fillColor = Color.FromArgb(baseAlpha, country.Color.R, country.Color.G, country.Color.B);
                var lightColor = Color.FromArgb(baseAlpha,
                    ClampToByte(country.Color.R + 25),
                    ClampToByte(country.Color.G + 25),
                    ClampToByte(country.Color.B + 25));
                var darkColor = Color.FromArgb(baseAlpha,
                    ClampToByte(country.Color.R * 0.7),
                    ClampToByte(country.Color.G * 0.7),
                    ClampToByte(country.Color.B * 0.7));

                var borderBrush = new SolidColorBrush(Color.FromArgb(220, 94, 234, 212));
                var borderPen = new Pen(borderBrush, 2);

                // Add pulse effect for active countries
                if (trafficValue > 0 && ShowAnimations)
                {
                    var pulse = Math.Sin(_animationPhase + country.Code.GetHashCode(StringComparison.Ordinal)) * 0.1 + 1.0;
                    radius *= pulse;
                }

                var center = country.GridPosition;
                var ellipseRect = new Rect(center.X - radius, center.Y - radius, radius * 2, radius * 2);

                var shadowBrush = new RadialGradientBrush
                {
                    Center = new RelativePoint(0.5, 0.5, RelativeUnit.Relative),
                    GradientStops = new GradientStops
                    {
                        new GradientStop { Color = Color.FromArgb(80, 0, 0, 0), Offset = 0 },
                        new GradientStop { Color = Color.FromArgb(0, 0, 0, 0), Offset = 1 }
                    }
                };
                var shadowRect = InflateRect(ellipseRect, 6, 6);
                var shadowCenter = new Point(shadowRect.X + shadowRect.Width / 2, shadowRect.Y + shadowRect.Height / 2);
                context.DrawEllipse(shadowBrush, null, shadowCenter, shadowRect.Width / 2, shadowRect.Height / 2);

                var fillBrush = new LinearGradientBrush
                {
                    StartPoint = new RelativePoint(ellipseRect.X, ellipseRect.Y, RelativeUnit.Absolute),
                    EndPoint = new RelativePoint(ellipseRect.X + ellipseRect.Width, ellipseRect.Y + ellipseRect.Height, RelativeUnit.Absolute),
                    GradientStops = new GradientStops
                    {
                        new GradientStop { Color = lightColor, Offset = 0 },
                        new GradientStop { Color = fillColor, Offset = 0.45 },
                        new GradientStop { Color = darkColor, Offset = 1 }
                    }
                };

                if (trafficValue > 50)
                {
                    var glowBrush = new RadialGradientBrush
                    {
                        GradientStops = new GradientStops
                        {
                            new GradientStop(Color.FromArgb(110, 47, 129, 247), 0),
                            new GradientStop(Color.FromArgb(0, 47, 129, 247), 1)
                        }
                    };
                    context.DrawEllipse(glowBrush, null, center, radius * 1.5, radius * 1.5);
                }

                context.DrawEllipse(fillBrush, null, center, radius, radius);
                context.DrawEllipse(null, borderPen, center, radius, radius);

                // Draw country code
                var textBrush = new SolidColorBrush(Colors.White);
                var typeface = new Typeface("Segoe UI");
                var formattedText = new FormattedText(
                    country.Code,
                    System.Globalization.CultureInfo.CurrentCulture,
                    FlowDirection.LeftToRight,
                    typeface,
                    14,
                    textBrush
                );
                
                var textPoint = new Point(
                    center.X - formattedText.Width / 2,
                    center.Y - formattedText.Height / 2
                );
                context.DrawText(formattedText, textPoint);
            }
        }

        private void DrawLabels(DrawingContext context)
        {
            var textBrush = new SolidColorBrush(Color.FromArgb(180, 255, 255, 255));
            var typeface = new Typeface("Segoe UI");
            
            foreach (var country in _countries.Values)
            {
                var trafficValue = CountryData?.GetValueOrDefault(country.Code, 0) ?? 0;
                if (trafficValue == 0) continue;
                
                var formattedText = new FormattedText(
                    $"{country.Name}\n{trafficValue:F1}%",
                    System.Globalization.CultureInfo.CurrentCulture,
                    FlowDirection.LeftToRight,
                    typeface,
                    10,
                    textBrush
                );
                
                var textPoint = new Point(
                    country.GridPosition.X - formattedText.Width / 2,
                    country.GridPosition.Y + 30
                );
                context.DrawText(formattedText, textPoint);
            }
        }

        private void DrawOverlay(DrawingContext context)
        {
            // Draw continent title
            var titleBrush = new SolidColorBrush(Colors.White);
            var titleTypeface = new Typeface("Segoe UI", FontStyle.Normal, FontWeight.Bold);
            var title = _continentName;
            if (string.Equals(_continentName, "Internal Network", StringComparison.OrdinalIgnoreCase))
            {
                title = "🏠 Internal Network";
            }
            else if (string.Equals(_continentName, "IPv6 Space", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(_continentName, "IPv6 Traffic", StringComparison.OrdinalIgnoreCase))
            {
                title = "🛰 IPv6 Space";
            }

            var titleText = new FormattedText(
                title.ToUpperInvariant(),
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                titleTypeface,
                24,
                titleBrush
            );
            context.DrawText(titleText, new Point(20, 20));
            
            // Draw statistics
            if (CountryData != null && CountryData.Any())
            {
                var statsBrush = new SolidColorBrush(Color.FromArgb(200, 255, 255, 255));
                var statsTypeface = new Typeface("Segoe UI");
                
                var totalTraffic = CountryData.Values.Sum();
                var activeCountries = CountryData.Count(kvp => kvp.Value > 0);
                var topCountry = CountryData.OrderByDescending(kvp => kvp.Value).FirstOrDefault();
                
                var statsText = $"Active Countries: {activeCountries}\n" +
                              $"Total Traffic: {totalTraffic:F1}%\n" +
                              $"Top: {topCountry.Key} ({topCountry.Value:F1}%)";
                
                var formattedStats = new FormattedText(
                    statsText,
                    System.Globalization.CultureInfo.CurrentCulture,
                    FlowDirection.LeftToRight,
                    statsTypeface,
                    12,
                    statsBrush
                );
                context.DrawText(formattedStats, new Point(20, 60));
            }
            
            // Draw zoom controls
            DrawZoomControls(context);
        }

        private void DrawZoomControls(DrawingContext context)
        {
            var x = Bounds.Width - 60;
            var y = 20;

            // Background
            var bgBrush = new SolidColorBrush(Color.FromArgb(180, 30, 30, 40));
            context.FillRectangle(bgBrush, new Rect(x, y, 40, 100));
            
            // Zoom in button
            var buttonBrush = new SolidColorBrush(Color.FromArgb(200, 47, 129, 247));
            var buttonPen = new Pen(buttonBrush, 1);
            context.DrawRectangle(buttonPen, new Rect(x + 5, y + 5, 30, 30));
            
            var textBrush = new SolidColorBrush(Colors.White);
            var typeface = new Typeface("Segoe UI");
            var plusText = new FormattedText(
                "+",
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                typeface,
                20,
                textBrush
            );
            context.DrawText(plusText, new Point(x + 13, y + 5));
            
            // Zoom out button
            context.DrawRectangle(buttonPen, new Rect(x + 5, y + 40, 30, 30));
            var minusText = new FormattedText(
                "-",
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                typeface,
                20,
                textBrush
            );
            context.DrawText(minusText, new Point(x + 15, y + 40));
            
            // Reset button
            context.DrawRectangle(buttonPen, new Rect(x + 5, y + 75, 30, 20));
            var resetText = new FormattedText(
                "R",
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                typeface,
                12,
                textBrush
            );
            context.DrawText(resetText, new Point(x + 15, y + 77));
        }

        private static byte ClampToByte(double value)
        {
            var clamped = Math.Clamp(value, 0d, 255d);
            return (byte)Math.Round(clamped);
        }

        private static Rect InflateRect(Rect rect, double dx, double dy)
        {
            var x = rect.X - dx;
            var y = rect.Y - dy;
            var width = rect.Width + dx * 2;
            var height = rect.Height + dy * 2;

            if (width < 0) width = 0;
            if (height < 0) height = 0;

            return new Rect(x, y, width, height);
        }

        private void DrawTooltip(DrawingContext context, Point position, string countryCode)
        {
            if (!_countries.ContainsKey(countryCode)) return;
            
            var country = _countries[countryCode];
            var traffic = CountryData?.GetValueOrDefault(countryCode, 0) ?? 0;
            
            var text = $"{country.Name} ({countryCode})\n" +
                      $"Traffic: {traffic:F1}%\n" +
                      $"Click for details";
            
            var typeface = new Typeface("Segoe UI");
            var formattedText = new FormattedText(
                text,
                System.Globalization.CultureInfo.CurrentCulture,
                FlowDirection.LeftToRight,
                typeface,
                11,
                new SolidColorBrush(Colors.White)
            );
            
            var padding = 8;
            var bgRect = new Rect(
                position.X + 10,
                position.Y - formattedText.Height - padding * 2,
                formattedText.Width + padding * 2,
                formattedText.Height + padding * 2
            );
            
            // Background
            var bgBrush = new SolidColorBrush(Color.FromArgb(230, 30, 30, 40));
            context.FillRectangle(bgBrush, bgRect);
            
            // Border
            var borderPen = new Pen(new SolidColorBrush(Color.FromArgb(200, 47, 129, 247)), 1);
            context.DrawRectangle(borderPen, bgRect);
            
            // Text
            context.DrawText(formattedText, new Point(bgRect.X + padding, bgRect.Y + padding));
        }

        private void OnPointerMoved(object? sender, PointerEventArgs e)
        {
            var point = e.GetPosition(this);
            
            if (_isPanning)
            {
                var delta = point - _lastPanPoint;
                _panOffset = new Point(_panOffset.X + delta.X, _panOffset.Y + delta.Y);
                _lastPanPoint = point;
                InvalidateVisual();
            }
            else
            {
                _hoveredPoint = point;
                _hoveredCountry = GetCountryAtPosition(point);
                InvalidateVisual();
            }
        }

        private void OnPointerPressed(object? sender, PointerPressedEventArgs e)
        {
            var point = e.GetPosition(this);
            var props = e.GetCurrentPoint(this).Properties;
            
            if (props.IsRightButtonPressed)
            {
                _isPanning = true;
                _lastPanPoint = point;
                e.Handled = true;
            }
            else if (props.IsLeftButtonPressed)
            {
                // Check if zoom controls were clicked
                var x = Bounds.Width - 60;
                var y = 20;
                
                if (point.X >= x && point.X <= x + 40)
                {
                    if (point.Y >= y + 5 && point.Y <= y + 35)
                    {
                        // Zoom in
                        _zoomLevel = Math.Min(_zoomLevel * 1.2, 5.0);
                        InvalidateVisual();
                    }
                    else if (point.Y >= y + 40 && point.Y <= y + 70)
                    {
                        // Zoom out
                        _zoomLevel = Math.Max(_zoomLevel / 1.2, 0.5);
                        InvalidateVisual();
                    }
                    else if (point.Y >= y + 75 && point.Y <= y + 95)
                    {
                        // Reset
                        _zoomLevel = 1.0;
                        _panOffset = new Point(0, 0);
                        InvalidateVisual();
                    }
                }
            }
        }

        private void OnPointerReleased(object? sender, PointerReleasedEventArgs e)
        {
            _isPanning = false;
        }

        private void OnPointerWheelChanged(object? sender, PointerWheelEventArgs e)
        {
            var delta = e.Delta.Y;
            if (delta > 0)
            {
                _zoomLevel = Math.Min(_zoomLevel * 1.1, 5.0);
            }
            else
            {
                _zoomLevel = Math.Max(_zoomLevel / 1.1, 0.5);
            }
            InvalidateVisual();
        }

        private void OnDoubleTapped(object? sender, TappedEventArgs e)
        {
            _zoomLevel = 1.0;
            _panOffset = new Point(0, 0);
            InvalidateVisual();
        }

        private string? GetCountryAtPosition(Point point)
        {
            // Apply inverse transform to get world coordinates
            var worldX = (point.X - _panOffset.X) / _zoomLevel;
            var worldY = (point.Y - _panOffset.Y) / _zoomLevel;
            var worldPoint = new Point(worldX, worldY);
            
            foreach (var country in _countries)
            {
                var distance = Math.Sqrt(
                    Math.Pow(worldPoint.X - country.Value.GridPosition.X, 2) +
                    Math.Pow(worldPoint.Y - country.Value.GridPosition.Y, 2)
                );
                
                if (distance < 30) // Detection radius
                {
                    return country.Key;
                }
            }
            
            return null;
        }

        private class CountryInfo
        {
            public string Code { get; set; } = "";
            public string Name { get; set; } = "";
            public Point GridPosition { get; set; }
            public Color Color { get; set; }
        }

        private class TrafficFlow
        {
            public string SourceCountry { get; set; } = "";
            public string DestinationCountry { get; set; } = "";
            public double Progress { get; set; }
            public Color Color { get; set; }
        }
    }
}
