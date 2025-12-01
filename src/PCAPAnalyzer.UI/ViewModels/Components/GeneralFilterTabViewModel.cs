using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class GeneralFilterTabViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    [ObservableProperty] private string _sourceIPInput = "";
    [ObservableProperty] private string _destinationIPInput = "";
    [ObservableProperty] private string _portRangeInput = "";

    // Observable chip collections with state tracking
    public ObservableCollection<FilterChipViewModel> ProtocolChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> SecurityChips { get; } = new();

    public GeneralFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
        InitializeChips();
    }

    private void InitializeChips()
    {
        // Protocol chips
        var protocols = new[] { "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "TLS", "SSH", "FTP", "SMTP" };
        foreach (var p in protocols)
            ProtocolChips.Add(new FilterChipViewModel(p, _filterState, FilterCategory.Protocol));

        // Security/Quick filter chips
        var security = new[] { "Insecure", "Anomalies", "Suspicious", "TCP Issues" };
        foreach (var s in security)
            SecurityChips.Add(new FilterChipViewModel(s, _filterState, FilterCategory.QuickFilter));
    }

    [RelayCommand]
    private void AddSourceIP()
    {
        if (string.IsNullOrWhiteSpace(SourceIPInput)) return;

        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeIP(SourceIPInput.Trim());
        else
            _filterState.AddExcludeIP(SourceIPInput.Trim());

        SourceIPInput = "";
    }

    [RelayCommand]
    private void AddDestinationIP()
    {
        if (string.IsNullOrWhiteSpace(DestinationIPInput)) return;

        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeIP(DestinationIPInput.Trim());
        else
            _filterState.AddExcludeIP(DestinationIPInput.Trim());

        DestinationIPInput = "";
    }

    [RelayCommand]
    private void AddPort()
    {
        if (string.IsNullOrWhiteSpace(PortRangeInput)) return;

        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludePort(PortRangeInput.Trim());
        else
            _filterState.AddExcludePort(PortRangeInput.Trim());

        PortRangeInput = "";
    }
}

public enum ChipState { Inactive, Included, Excluded }
