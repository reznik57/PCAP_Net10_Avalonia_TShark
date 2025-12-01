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

    // Predefined protocol chips
    public static readonly string[] ProtocolChips =
        { "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "TLS", "SSH", "FTP", "SMTP" };

    public static readonly string[] SecurityChips =
        { "Insecure", "Anomalies", "Suspicious", "TCP Issues" };

    public static readonly string[] TlsChips =
        { "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" };

    public GeneralFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
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

    [RelayCommand]
    private void ToggleProtocol(string protocol)
    {
        // Check if already in include list
        if (_filterState.IncludeFilters.Protocols.Contains(protocol))
        {
            _filterState.RemoveIncludeFilter(protocol, FilterCategory.Protocol);
            return;
        }

        // Check if already in exclude list
        if (_filterState.ExcludeFilters.Protocols.Contains(protocol))
        {
            _filterState.RemoveExcludeFilter(protocol, FilterCategory.Protocol);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeProtocol(protocol);
        else
            _filterState.AddExcludeProtocol(protocol);
    }

    [RelayCommand]
    private void ToggleQuickFilter(string filter)
    {
        if (_filterState.IncludeFilters.QuickFilters.Contains(filter))
        {
            _filterState.RemoveIncludeFilter(filter, FilterCategory.QuickFilter);
            return;
        }

        if (_filterState.ExcludeFilters.QuickFilters.Contains(filter))
        {
            _filterState.RemoveExcludeFilter(filter, FilterCategory.QuickFilter);
            return;
        }

        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeQuickFilter(filter);
        else
            _filterState.AddExcludeQuickFilter(filter);
    }

    // Helper to check chip state for UI styling
    public ChipState GetProtocolChipState(string protocol)
    {
        if (_filterState.IncludeFilters.Protocols.Contains(protocol))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.Protocols.Contains(protocol))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }

    public ChipState GetQuickFilterChipState(string filter)
    {
        if (_filterState.IncludeFilters.QuickFilters.Contains(filter))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.QuickFilters.Contains(filter))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }
}

public enum ChipState { Inactive, Included, Excluded }
