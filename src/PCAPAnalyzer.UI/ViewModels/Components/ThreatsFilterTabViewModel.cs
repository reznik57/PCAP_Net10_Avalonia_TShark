using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class ThreatsFilterTabViewModel : ObservableObject
{
    // ==================== SEARCH & DROPDOWNS ====================
    [ObservableProperty] private string _searchInput = "";
    [ObservableProperty] private string _selectedCategory = "All";
    [ObservableProperty] private string _selectedThreatType = "All";

    // Available categories for dropdown
    public ObservableCollection<string> Categories { get; } = new()
    {
        "All", "CleartextCredentials", "InsecureProtocol", "WeakEncryption",
        "PortScan", "BruteForce", "DataExfiltration", "Malware", "C2Communication"
    };

    // Threat types populated dynamically from detected threats
    public ObservableCollection<string> ThreatTypes { get; } = new() { "All" };

    // ==================== SEVERITY & CATEGORY CHIPS ====================
    public ObservableCollection<FilterChipViewModel> SeverityChips { get; } = [];
    public ObservableCollection<FilterChipViewModel> ThreatCategoryChips { get; } = [];

    // ==================== QUICK FILTER TOGGLES (OR logic) ====================
    [ObservableProperty] private bool _showCriticalOnly;
    [ObservableProperty] private bool _showHighOnly;
    [ObservableProperty] private bool _isInsecureProtocolFilterActive;
    [ObservableProperty] private bool _isKnownCVEFilterActive;
    [ObservableProperty] private bool _isWeakEncryptionFilterActive;
    [ObservableProperty] private bool _isAuthIssuesFilterActive;
    [ObservableProperty] private bool _isCleartextFilterActive;

    // Mutual exclusion for Critical/High+
    partial void OnShowCriticalOnlyChanged(bool value)
    {
        if (value) ShowHighOnly = false;
        OnPropertyChanged(nameof(HasActiveQuickFilters));
        FiltersChanged?.Invoke();
    }

    partial void OnShowHighOnlyChanged(bool value)
    {
        if (value) ShowCriticalOnly = false;
        OnPropertyChanged(nameof(HasActiveQuickFilters));
        FiltersChanged?.Invoke();
    }

    partial void OnIsInsecureProtocolFilterActiveChanged(bool value)
    {
        OnPropertyChanged(nameof(HasActiveQuickFilters));
        FiltersChanged?.Invoke();
    }

    partial void OnIsKnownCVEFilterActiveChanged(bool value)
    {
        OnPropertyChanged(nameof(HasActiveQuickFilters));
        FiltersChanged?.Invoke();
    }

    partial void OnIsWeakEncryptionFilterActiveChanged(bool value)
    {
        OnPropertyChanged(nameof(HasActiveQuickFilters));
        FiltersChanged?.Invoke();
    }

    partial void OnIsAuthIssuesFilterActiveChanged(bool value)
    {
        OnPropertyChanged(nameof(HasActiveQuickFilters));
        FiltersChanged?.Invoke();
    }

    partial void OnIsCleartextFilterActiveChanged(bool value)
    {
        OnPropertyChanged(nameof(HasActiveQuickFilters));
        FiltersChanged?.Invoke();
    }

    /// <summary>
    /// Returns true if any quick filter toggle is active
    /// </summary>
    public bool HasActiveQuickFilters =>
        ShowCriticalOnly || ShowHighOnly ||
        IsInsecureProtocolFilterActive || IsKnownCVEFilterActive ||
        IsWeakEncryptionFilterActive || IsAuthIssuesFilterActive ||
        IsCleartextFilterActive;

    /// <summary>
    /// Event fired when filters change (for real-time updates)
    /// </summary>
    public event Action? FiltersChanged;

    public ThreatsFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        var severities = new[] { "Critical", "High", "Medium", "Low" };
        foreach (var s in severities)
            SeverityChips.Add(new FilterChipViewModel(s));

        var categories = new[] { "Network", "Application", "Crypto", "Exfiltration", "IoT", "VoIP" };
        foreach (var c in categories)
            ThreatCategoryChips.Add(new FilterChipViewModel(c));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in SeverityChips) chip.SetMode(mode);
        foreach (var chip in ThreatCategoryChips) chip.SetMode(mode);
    }

    public (List<string> Severities, List<string> Categories) GetPendingFilters()
    {
        return (
            SeverityChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            ThreatCategoryChips.Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    /// <summary>
    /// Gets the current quick filter state for application
    /// </summary>
    public ThreatQuickFilters GetQuickFilters()
    {
        return new ThreatQuickFilters
        {
            SearchInput = SearchInput,
            SelectedCategory = SelectedCategory,
            SelectedThreatType = SelectedThreatType,
            ShowCriticalOnly = ShowCriticalOnly,
            ShowHighOnly = ShowHighOnly,
            IsInsecureProtocolFilterActive = IsInsecureProtocolFilterActive,
            IsKnownCVEFilterActive = IsKnownCVEFilterActive,
            IsWeakEncryptionFilterActive = IsWeakEncryptionFilterActive,
            IsAuthIssuesFilterActive = IsAuthIssuesFilterActive,
            IsCleartextFilterActive = IsCleartextFilterActive
        };
    }

    [RelayCommand]
    private void ClearQuickFilters()
    {
        ShowCriticalOnly = false;
        ShowHighOnly = false;
        IsInsecureProtocolFilterActive = false;
        IsKnownCVEFilterActive = false;
        IsWeakEncryptionFilterActive = false;
        IsAuthIssuesFilterActive = false;
        IsCleartextFilterActive = false;
        SearchInput = "";
        SelectedCategory = "All";
        SelectedThreatType = "All";
    }

    public void Reset()
    {
        foreach (var chip in SeverityChips) chip.Reset();
        foreach (var chip in ThreatCategoryChips) chip.Reset();
        ClearQuickFilters();
    }

    /// <summary>
    /// Updates the ThreatTypes dropdown with detected threat names
    /// </summary>
    public void UpdateThreatTypes(IEnumerable<string> threatNames)
    {
        ThreatTypes.Clear();
        ThreatTypes.Add("All");
        foreach (var name in threatNames.Distinct().OrderBy(n => n))
        {
            ThreatTypes.Add(name);
        }
    }
}

/// <summary>
/// Data transfer object for threat quick filter state
/// </summary>
public class ThreatQuickFilters
{
    public string SearchInput { get; set; } = "";
    public string SelectedCategory { get; set; } = "All";
    public string SelectedThreatType { get; set; } = "All";
    public bool ShowCriticalOnly { get; set; }
    public bool ShowHighOnly { get; set; }
    public bool IsInsecureProtocolFilterActive { get; set; }
    public bool IsKnownCVEFilterActive { get; set; }
    public bool IsWeakEncryptionFilterActive { get; set; }
    public bool IsAuthIssuesFilterActive { get; set; }
    public bool IsCleartextFilterActive { get; set; }

    public bool HasAnyFilter =>
        !string.IsNullOrEmpty(SearchInput) ||
        SelectedCategory != "All" ||
        SelectedThreatType != "All" ||
        ShowCriticalOnly || ShowHighOnly ||
        IsInsecureProtocolFilterActive || IsKnownCVEFilterActive ||
        IsWeakEncryptionFilterActive || IsAuthIssuesFilterActive ||
        IsCleartextFilterActive;
}
