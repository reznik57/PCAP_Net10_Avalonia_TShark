using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages anomaly-specific filter state (severity, category, detector chips).
/// </summary>
public partial class AnomaliesFilterViewModel : ObservableObject
{
    private readonly GlobalFilterState _globalFilterState;

    // Severity toggles
    [ObservableProperty] private bool _isCriticalSelected;
    [ObservableProperty] private bool _isHighSelected;
    [ObservableProperty] private bool _isMediumSelected;
    [ObservableProperty] private bool _isLowSelected;

    // Category toggles
    [ObservableProperty] private bool _isNetworkSelected;
    [ObservableProperty] private bool _isTcpSelected;
    [ObservableProperty] private bool _isApplicationSelected;
    [ObservableProperty] private bool _isVoipSelected;
    [ObservableProperty] private bool _isIotSelected;
    [ObservableProperty] private bool _isSecuritySelected;
    [ObservableProperty] private bool _isMalformedSelected;

    // Available detectors (populated from service)
    public ObservableCollection<DetectorToggle> AvailableDetectors { get; } = [];

    public event EventHandler? FiltersChanged;

    public AnomaliesFilterViewModel(GlobalFilterState globalFilterState)
    {
        _globalFilterState = globalFilterState;

        // Initialize from global state if already set
        SyncFromGlobalState();
    }

    private void SyncFromGlobalState()
    {
        var severities = _globalFilterState.AnomalySeverityFilter;
        IsCriticalSelected = severities.Contains(AnomalySeverity.Critical);
        IsHighSelected = severities.Contains(AnomalySeverity.High);
        IsMediumSelected = severities.Contains(AnomalySeverity.Medium);
        IsLowSelected = severities.Contains(AnomalySeverity.Low);

        var categories = _globalFilterState.AnomalyCategoryFilter;
        IsNetworkSelected = categories.Contains(AnomalyCategory.Network);
        IsTcpSelected = categories.Contains(AnomalyCategory.TCP);
        IsApplicationSelected = categories.Contains(AnomalyCategory.Application);
        IsVoipSelected = categories.Contains(AnomalyCategory.VoIP);
        IsIotSelected = categories.Contains(AnomalyCategory.IoT);
        IsSecuritySelected = categories.Contains(AnomalyCategory.Security);
        IsMalformedSelected = categories.Contains(AnomalyCategory.Malformed);
    }

    partial void OnIsCriticalSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsHighSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsMediumSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsLowSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsNetworkSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsTcpSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsApplicationSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsVoipSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsIotSelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsSecuritySelectedChanged(bool value) => UpdateGlobalFilters();
    partial void OnIsMalformedSelectedChanged(bool value) => UpdateGlobalFilters();

    private void UpdateGlobalFilters()
    {
        // Update severity filters
        var severities = new List<AnomalySeverity>();
        if (IsCriticalSelected) severities.Add(AnomalySeverity.Critical);
        if (IsHighSelected) severities.Add(AnomalySeverity.High);
        if (IsMediumSelected) severities.Add(AnomalySeverity.Medium);
        if (IsLowSelected) severities.Add(AnomalySeverity.Low);
        _globalFilterState.AnomalySeverityFilter = severities;

        // Update category filters
        var categories = new List<AnomalyCategory>();
        if (IsNetworkSelected) categories.Add(AnomalyCategory.Network);
        if (IsTcpSelected) categories.Add(AnomalyCategory.TCP);
        if (IsApplicationSelected) categories.Add(AnomalyCategory.Application);
        if (IsVoipSelected) categories.Add(AnomalyCategory.VoIP);
        if (IsIotSelected) categories.Add(AnomalyCategory.IoT);
        if (IsSecuritySelected) categories.Add(AnomalyCategory.Security);
        if (IsMalformedSelected) categories.Add(AnomalyCategory.Malformed);
        _globalFilterState.AnomalyCategoryFilter = categories;

        // Update detector filters
        var detectors = AvailableDetectors
            .Where(d => d.IsSelected)
            .Select(d => d.Name)
            .ToList();
        _globalFilterState.AnomalyDetectorFilter = detectors;

        FiltersChanged?.Invoke(this, EventArgs.Empty);
    }

    public void SetAvailableDetectors(IEnumerable<string> detectorNames)
    {
        AvailableDetectors.Clear();
        foreach (var name in detectorNames)
        {
            var toggle = new DetectorToggle(name);
            toggle.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(DetectorToggle.IsSelected))
                    UpdateGlobalFilters();
            };
            AvailableDetectors.Add(toggle);
        }
    }

    [RelayCommand]
    private void ClearAllFilters()
    {
        IsCriticalSelected = false;
        IsHighSelected = false;
        IsMediumSelected = false;
        IsLowSelected = false;
        IsNetworkSelected = false;
        IsTcpSelected = false;
        IsApplicationSelected = false;
        IsVoipSelected = false;
        IsIotSelected = false;
        IsSecuritySelected = false;
        IsMalformedSelected = false;

        foreach (var detector in AvailableDetectors)
            detector.IsSelected = false;

        _globalFilterState.ClearAnomalyFilters();
        FiltersChanged?.Invoke(this, EventArgs.Empty);
    }

    public bool HasActiveFilters =>
        IsCriticalSelected || IsHighSelected || IsMediumSelected || IsLowSelected ||
        IsNetworkSelected || IsTcpSelected || IsApplicationSelected || IsVoipSelected ||
        IsIotSelected || IsSecuritySelected || IsMalformedSelected ||
        AvailableDetectors.Any(d => d.IsSelected);
}

/// <summary>
/// Toggle state for a single detector.
/// </summary>
public partial class DetectorToggle : ObservableObject
{
    public string Name { get; }
    public string DisplayName { get; }

    [ObservableProperty] private bool _isSelected;

    public DetectorToggle(string name)
    {
        Name = name;
        DisplayName = name.Replace("Detector", "", StringComparison.Ordinal).Replace("Anomaly", "", StringComparison.Ordinal).Trim();
    }
}
