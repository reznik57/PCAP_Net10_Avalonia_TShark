using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Utilities;
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
    private HashSet<string> _excludedCountries = [];

    // Static color references for theme consistency
    private static readonly string DefaultContinentColor = ThemeColorHelper.GetColorHex("BackgroundLevel1", "#1C2128");
    private static readonly string ColorMuted = ThemeColorHelper.GetColorHex("TextMuted", "#6B7280");
    private static readonly string ColorHighRisk = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
    private static readonly string ColorHighTraffic = ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444");
    private static readonly string ColorMediumTraffic = ThemeColorHelper.GetColorHex("ColorOrange", "#F97316");
    private static readonly string ColorLowTraffic = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");

    // Chart colors - delegate to centralized palette
    private static string[] ChartColors => ThemeColorHelper.GetChartColorPalette();

    // Chart data
    [ObservableProperty] private ObservableCollection<ISeries> _countryChartSeries = [];

    // Map data
    [ObservableProperty] private Dictionary<string, double> _countryMapData = [];

    // Continent colors based on traffic
    [ObservableProperty] private string _northAmericaColor = DefaultContinentColor;
    [ObservableProperty] private string _southAmericaColor = DefaultContinentColor;
    [ObservableProperty] private string _europeColor = DefaultContinentColor;
    [ObservableProperty] private string _africaColor = DefaultContinentColor;
    [ObservableProperty] private string _asiaColor = DefaultContinentColor;
    [ObservableProperty] private string _oceaniaColor = DefaultContinentColor;
    [ObservableProperty] private string _internalColor = DefaultContinentColor;
    [ObservableProperty] private string _ipv6Color = DefaultContinentColor;

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
        if (_currentStatistics?.CountryStatistics is null || !_currentStatistics.CountryStatistics.Any())
        {
            CountryChartSeries = new ObservableCollection<ISeries>
            {
                new PieSeries<double>
                {
                    Values = new[] { 1.0 },
                    Name = "No Data",
                    Fill = ThemeColorHelper.ParseSolidColorPaint(ColorMuted)
                }
            };
            DebugLogger.Log("[CountryVisualizationViewModel] No country statistics - showing 'No Data' chart");
            return;
        }

        var series = new ObservableCollection<ISeries>();

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
            var color = country.IsHighRisk ? ColorHighRisk : ChartColors[colorIndex % ChartColors.Length];
            series.Add(new PieSeries<double>
            {
                Values = new[] { (double)country.TotalPackets },
                Name = $"{country.CountryName} ({country.Percentage:F1}%)",
                Fill = ThemeColorHelper.ParseSolidColorPaint(color),
                DataLabelsPaint = ThemeColorHelper.WhitePaint,
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
                Fill = ThemeColorHelper.ParseSolidColorPaint(ColorMuted),
                DataLabelsPaint = ThemeColorHelper.WhitePaint,
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

        if (_currentStatistics?.CountryStatistics is not null)
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
        if (_currentStatistics?.CountryStatistics is null)
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
        NorthAmericaColor = DefaultContinentColor;
        SouthAmericaColor = DefaultContinentColor;
        EuropeColor = DefaultContinentColor;
        AfricaColor = DefaultContinentColor;
        AsiaColor = DefaultContinentColor;
        OceaniaColor = DefaultContinentColor;
        InternalColor = DefaultContinentColor;
        Ipv6Color = DefaultContinentColor;
    }

    /// <summary>
    /// Gets traffic-based color for a continent
    /// </summary>
    private string GetTrafficColor(long traffic, long maxTraffic)
    {
        if (traffic == 0) return DefaultContinentColor;

        var ratio = (double)traffic / maxTraffic;
        return ratio switch
        {
            > 0.66 => ColorHighTraffic,
            > 0.33 => ColorMediumTraffic,
            > 0 => ColorLowTraffic,
            _ => DefaultContinentColor
        };
    }

    /// <summary>
    /// Gets continent name from country code for use as dictionary key.
    /// Uses centralized ContinentData mapping.
    /// </summary>
    private static string GetContinentName(string countryCode)
    {
        var code = ContinentData.GetContinentCode(countryCode);
        return code switch
        {
            "NA" => "NorthAmerica",
            "SA" => "SouthAmerica",
            "EU" => "Europe",
            "AS" => "Asia",
            "AF" => "Africa",
            "OC" => "Oceania",
            "INT" => "Internal",
            "IP6" => "IPv6",
            _ => "Asia" // Default fallback
        };
    }
}
