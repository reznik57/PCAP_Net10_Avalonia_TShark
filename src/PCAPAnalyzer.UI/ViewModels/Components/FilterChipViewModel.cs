using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Represents a single filter chip with visual state tracking.
/// </summary>
public partial class FilterChipViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;
    private readonly FilterCategory _category;

    public string Name { get; }

    [ObservableProperty] private bool _isIncluded;
    [ObservableProperty] private bool _isExcluded;

    public string StateClass => IsIncluded ? "chip-included" : IsExcluded ? "chip-excluded" : "";

    public FilterChipViewModel(string name, GlobalFilterState filterState, FilterCategory category)
    {
        Name = name;
        _filterState = filterState;
        _category = category;

        // Subscribe to filter changes
        _filterState.OnFilterChanged += RefreshState;
        RefreshState();
    }

    private void RefreshState()
    {
        var wasIncluded = IsIncluded;
        var wasExcluded = IsExcluded;

        IsIncluded = _category switch
        {
            FilterCategory.Protocol => _filterState.IncludeFilters.Protocols.Contains(Name),
            FilterCategory.QuickFilter => _filterState.IncludeFilters.QuickFilters.Contains(Name),
            FilterCategory.Severity => _filterState.IncludeFilters.Severities.Contains(Name),
            FilterCategory.ThreatCategory => _filterState.IncludeFilters.ThreatCategories.Contains(Name),
            FilterCategory.Codec => _filterState.IncludeFilters.Codecs.Contains(Name),
            FilterCategory.QualityLevel => _filterState.IncludeFilters.QualityLevels.Contains(Name),
            FilterCategory.VoipIssue => _filterState.IncludeFilters.VoipIssues.Contains(Name),
            FilterCategory.Country => _filterState.IncludeFilters.Countries.Contains(Name),
            FilterCategory.Direction => _filterState.IncludeFilters.Directions.Contains(Name),
            FilterCategory.Region => _filterState.IncludeFilters.Regions.Contains(Name),
            _ => false
        };

        IsExcluded = _category switch
        {
            FilterCategory.Protocol => _filterState.ExcludeFilters.Protocols.Contains(Name),
            FilterCategory.QuickFilter => _filterState.ExcludeFilters.QuickFilters.Contains(Name),
            FilterCategory.Severity => _filterState.ExcludeFilters.Severities.Contains(Name),
            FilterCategory.ThreatCategory => _filterState.ExcludeFilters.ThreatCategories.Contains(Name),
            FilterCategory.Codec => _filterState.ExcludeFilters.Codecs.Contains(Name),
            FilterCategory.QualityLevel => _filterState.ExcludeFilters.QualityLevels.Contains(Name),
            FilterCategory.VoipIssue => _filterState.ExcludeFilters.VoipIssues.Contains(Name),
            FilterCategory.Country => _filterState.ExcludeFilters.Countries.Contains(Name),
            FilterCategory.Direction => _filterState.ExcludeFilters.Directions.Contains(Name),
            FilterCategory.Region => _filterState.ExcludeFilters.Regions.Contains(Name),
            _ => false
        };

        if (wasIncluded != IsIncluded || wasExcluded != IsExcluded)
        {
            OnPropertyChanged(nameof(StateClass));
        }
    }

    [RelayCommand]
    private void Toggle()
    {
        // If already in include list, remove it
        if (IsIncluded)
        {
            _filterState.RemoveIncludeFilter(Name, _category);
            return;
        }

        // If already in exclude list, remove it
        if (IsExcluded)
        {
            _filterState.RemoveExcludeFilter(Name, _category);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            AddToInclude();
        else
            AddToExclude();
    }

    private void AddToInclude()
    {
        switch (_category)
        {
            case FilterCategory.Protocol:
                _filterState.AddIncludeProtocol(Name);
                break;
            case FilterCategory.QuickFilter:
                _filterState.AddIncludeQuickFilter(Name);
                break;
            case FilterCategory.Severity:
                _filterState.AddIncludeSeverity(Name);
                break;
            case FilterCategory.ThreatCategory:
                _filterState.AddIncludeThreatCategory(Name);
                break;
            case FilterCategory.Codec:
                _filterState.AddIncludeCodec(Name);
                break;
            case FilterCategory.QualityLevel:
                _filterState.AddIncludeQualityLevel(Name);
                break;
            case FilterCategory.VoipIssue:
                _filterState.AddIncludeVoipIssue(Name);
                break;
            case FilterCategory.Country:
                _filterState.AddIncludeCountry(Name);
                break;
            case FilterCategory.Direction:
                _filterState.AddIncludeDirection(Name);
                break;
            case FilterCategory.Region:
                _filterState.AddIncludeRegion(Name);
                break;
        }
    }

    private void AddToExclude()
    {
        switch (_category)
        {
            case FilterCategory.Protocol:
                _filterState.AddExcludeProtocol(Name);
                break;
            case FilterCategory.QuickFilter:
                _filterState.AddExcludeQuickFilter(Name);
                break;
            case FilterCategory.Severity:
                _filterState.AddExcludeSeverity(Name);
                break;
            case FilterCategory.ThreatCategory:
                _filterState.AddExcludeThreatCategory(Name);
                break;
            case FilterCategory.Codec:
                _filterState.AddExcludeCodec(Name);
                break;
            case FilterCategory.QualityLevel:
                _filterState.AddExcludeQualityLevel(Name);
                break;
            case FilterCategory.VoipIssue:
                _filterState.AddExcludeVoipIssue(Name);
                break;
            case FilterCategory.Country:
                _filterState.AddExcludeCountry(Name);
                break;
            case FilterCategory.Direction:
                _filterState.AddExcludeDirection(Name);
                break;
            case FilterCategory.Region:
                _filterState.AddExcludeRegion(Name);
                break;
        }
    }
}
