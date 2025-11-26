using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using SkiaSharp;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for all country traffic visualization (charts, maps, colors).
/// Handles pie charts, map data preparation, and continent color coding based on traffic.
/// </summary>
public partial class CountryVisualizationViewModel : ObservableObject
{
    private NetworkStatistics? _currentStatistics;
    private HashSet<string> _excludedCountries = new();

    // Chart data
    [ObservableProperty] private ObservableCollection<ISeries> _countryChartSeries = new();

    // Map data
    [ObservableProperty] private Dictionary<string, double> _countryMapData = new();

    // Continent colors based on traffic
    [ObservableProperty] private string _northAmericaColor = "#1C2128";
    [ObservableProperty] private string _southAmericaColor = "#1C2128";
    [ObservableProperty] private string _europeColor = "#1C2128";
    [ObservableProperty] private string _africaColor = "#1C2128";
    [ObservableProperty] private string _asiaColor = "#1C2128";
    [ObservableProperty] private string _oceaniaColor = "#1C2128";
    [ObservableProperty] private string _internalColor = "#1C2128";
    [ObservableProperty] private string _ipv6Color = "#1C2128";

    /// <summary>
    /// Event raised when visualization data has been updated
    /// </summary>
    public event EventHandler? VisualizationUpdated;

    /// <summary>
    /// Sets the current statistics for visualization
    /// </summary>
    public void SetStatistics(NetworkStatistics? statistics)
    {
        _currentStatistics = statistics;
    }

    /// <summary>
    /// Sets the excluded countries for filtering
    /// </summary>
    public void SetExcludedCountries(IEnumerable<string> excluded)
    {
        _excludedCountries = new HashSet<string>(excluded, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Updates all visualizations
    /// </summary>
    public void UpdateVisualizations()
    {
        UpdateCountryChart();
        UpdateCountryMapData();
        UpdateContinentColors();
        VisualizationUpdated?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Updates the country pie chart
    /// </summary>
    public void UpdateCountryChart()
    {
        if (_currentStatistics?.CountryStatistics == null || !_currentStatistics.CountryStatistics.Any())
        {
            CountryChartSeries = new ObservableCollection<ISeries>
            {
                new PieSeries<double>
                {
                    Values = new[] { 1.0 },
                    Name = "No Data",
                    Fill = new SolidColorPaint(SKColor.Parse("#6B7280"))
                }
            };
            DebugLogger.Log("[CountryVisualizationViewModel] No country statistics - showing 'No Data' chart");
            return;
        }

        var series = new ObservableCollection<ISeries>();
        var colors = new[]
        {
            "#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6",
            "#EC4899", "#14B8A6", "#F97316", "#6366F1", "#84CC16"
        };

        // Filter excluded countries
        var filteredCountries = _currentStatistics.CountryStatistics.Values
            .Where(c => !_excludedCountries.Contains(c.CountryCode))
            .ToList();

        var topCountries = filteredCountries
            .OrderByDescending(c => c.TotalPackets)
            .Take(8)
            .ToList();

        var otherPackets = filteredCountries
            .Skip(8)
            .Sum(c => c.TotalPackets);

        int colorIndex = 0;
        foreach (var country in topCountries)
        {
            var color = country.IsHighRisk ? "#DC2626" : colors[colorIndex % colors.Length];
            series.Add(new PieSeries<double>
            {
                Values = new[] { (double)country.TotalPackets },
                Name = $"{country.CountryName} ({country.Percentage:F1}%)",
                Fill = new SolidColorPaint(SKColor.Parse(color)),
                DataLabelsPaint = new SolidColorPaint(SKColors.White),
                DataLabelsSize = 12,
                DataLabelsPosition = LiveChartsCore.Measure.PolarLabelsPosition.Middle,
                DataLabelsFormatter = point => country.Percentage > 5 ? country.CountryCode : "",
                InnerRadius = 60
            });
            colorIndex++;
        }

        // Add "Others" if there are more countries
        if (otherPackets > 0)
        {
            // Calculate total packets from filtered countries
            var totalCountryPackets = filteredCountries.Sum(c => c.TotalPackets);
            var othersPercentage = totalCountryPackets > 0 ? (double)otherPackets / totalCountryPackets * 100 : 0;
            series.Add(new PieSeries<double>
            {
                Values = new[] { (double)otherPackets },
                Name = $"Others ({othersPercentage:F1}%)",
                Fill = new SolidColorPaint(SKColor.Parse("#6B7280")),
                DataLabelsPaint = new SolidColorPaint(SKColors.White),
                DataLabelsSize = 12,
                InnerRadius = 60
            });
        }

        CountryChartSeries = series;
        DebugLogger.Log($"[CountryVisualizationViewModel] Updated chart with {series.Count} series");
    }

    /// <summary>
    /// Updates the country map data
    /// </summary>
    public void UpdateCountryMapData()
    {
        var mapData = new Dictionary<string, double>();

        if (_currentStatistics?.CountryStatistics != null)
        {
            DebugLogger.Log($"[CountryVisualizationViewModel] UpdateCountryMapData: Processing {_currentStatistics.CountryStatistics.Count} countries for map");

            foreach (var country in _currentStatistics.CountryStatistics.Values)
            {
                // Skip excluded countries
                if (_excludedCountries.Contains(country.CountryCode))
                    continue;

                // Use percentage for map visualization
                mapData[country.CountryCode] = country.Percentage;
            }

            DebugLogger.Log($"[CountryVisualizationViewModel] UpdateCountryMapData: Added {mapData.Count} countries to map data");
            var mapCountryCodes = mapData.Keys.OrderBy(k => k).ToList();
            DebugLogger.Log($"[CountryVisualizationViewModel] Map country codes: {string.Join(", ", mapCountryCodes.Take(10))}...");
        }

        CountryMapData = mapData;
    }

    /// <summary>
    /// Updates continent colors based on traffic intensity
    /// </summary>
    public void UpdateContinentColors()
    {
        if (_currentStatistics?.CountryStatistics == null)
        {
            ResetContinentColors();
            return;
        }

        // Aggregate traffic by continent
        var continentTraffic = new Dictionary<string, long>
        {
            ["NorthAmerica"] = 0,
            ["SouthAmerica"] = 0,
            ["Europe"] = 0,
            ["Africa"] = 0,
            ["Asia"] = 0,
            ["Oceania"] = 0,
            ["Internal"] = 0,
            ["IPv6"] = 0
        };

        foreach (var country in _currentStatistics.CountryStatistics.Values)
        {
            // Skip excluded countries
            if (_excludedCountries.Contains(country.CountryCode))
                continue;

            var continent = GetContinentName(country.CountryCode);
            if (continentTraffic.ContainsKey(continent))
            {
                continentTraffic[continent] += country.TotalPackets;
            }
        }

        // Find max traffic for color scaling
        var maxTraffic = continentTraffic.Values.Max();
        if (maxTraffic == 0)
        {
            ResetContinentColors();
            return;
        }

        // Update colors and traffic stats
        NorthAmericaColor = GetTrafficColor(continentTraffic["NorthAmerica"], maxTraffic);
        SouthAmericaColor = GetTrafficColor(continentTraffic["SouthAmerica"], maxTraffic);
        EuropeColor = GetTrafficColor(continentTraffic["Europe"], maxTraffic);
        AfricaColor = GetTrafficColor(continentTraffic["Africa"], maxTraffic);
        AsiaColor = GetTrafficColor(continentTraffic["Asia"], maxTraffic);
        OceaniaColor = GetTrafficColor(continentTraffic["Oceania"], maxTraffic);
        InternalColor = GetTrafficColor(continentTraffic["Internal"], maxTraffic);
        Ipv6Color = GetTrafficColor(continentTraffic["IPv6"], maxTraffic);

        DebugLogger.Log($"[CountryVisualizationViewModel] Updated continent colors - Max traffic: {maxTraffic:N0}");
    }

    /// <summary>
    /// Resets all continent colors to default
    /// </summary>
    private void ResetContinentColors()
    {
        NorthAmericaColor = "#1C2128";
        SouthAmericaColor = "#1C2128";
        EuropeColor = "#1C2128";
        AfricaColor = "#1C2128";
        AsiaColor = "#1C2128";
        OceaniaColor = "#1C2128";
        InternalColor = "#1C2128";
        Ipv6Color = "#1C2128";
    }

    /// <summary>
    /// Gets traffic-based color for a continent
    /// </summary>
    private string GetTrafficColor(long traffic, long maxTraffic)
    {
        if (traffic == 0) return "#1C2128"; // No traffic - dark gray

        var ratio = (double)traffic / maxTraffic;
        return ratio switch
        {
            > 0.66 => "#EF4444", // High traffic - red
            > 0.33 => "#F97316", // Medium traffic - orange
            > 0 => "#3B82F6",    // Low traffic - blue
            _ => "#1C2128"       // No traffic - dark gray
        };
    }

    /// <summary>
    /// Gets continent name from country code
    /// </summary>
    private string GetContinentName(string countryCode)
    {
        // Handle special cases
        if (countryCode == "INTERNAL" || countryCode == "PRIV") return "Internal";
        if (countryCode == "IPV6" || countryCode == "IP6") return "IPv6";

        // North America
        if (new[] { "US", "CA", "MX" }.Contains(countryCode)) return "NorthAmerica";

        // South America
        if (new[] { "BR", "AR", "CL", "CO", "PE", "VE", "EC", "BO", "UY", "PY", "GY", "SR", "GF" }.Contains(countryCode))
            return "SouthAmerica";

        // Europe
        if (new[] { "GB", "FR", "DE", "IT", "ES", "NL", "BE", "SE", "NO", "DK", "FI", "PL", "UA", "RO", "CZ", "PT", "GR", "HU", "AT", "CH", "IE", "BG", "RS", "HR", "SK", "LT", "SI", "LV", "EE", "LU", "MT", "CY", "IS", "AL", "MK", "ME", "BA", "MD", "BY", "XK" }.Contains(countryCode))
            return "Europe";

        // Africa
        if (new[] { "ZA", "EG", "NG", "KE", "GH", "TZ", "UG", "DZ", "MA", "AO", "SD", "ET", "MZ", "MG", "CM", "CI", "NE", "BF", "ML", "MW", "ZM", "SN", "SO", "TD", "ZW", "GN", "RW", "BJ", "TN", "BI", "SS", "TG", "SL", "LY", "LR", "MR", "CF", "ER", "GM", "BW", "GA", "GW", "GQ", "MU", "SZ", "DJ", "RE", "KM", "CV", "ST", "SC" }.Contains(countryCode))
            return "Africa";

        // Oceania
        if (new[] { "AU", "NZ", "PG", "FJ", "NC", "PF", "SB", "GU", "VU", "FM", "KI", "MH", "PW", "NR", "TO", "AS", "MP", "WS", "TV" }.Contains(countryCode))
            return "Oceania";

        // Default to Asia
        return "Asia";
    }
}
