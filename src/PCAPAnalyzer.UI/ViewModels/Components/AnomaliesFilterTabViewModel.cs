using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class AnomaliesFilterTabViewModel : ObservableObject
{
    [ObservableProperty] private string _searchInput = "";

    public ObservableCollection<FilterChipViewModel> SeverityChips { get; } = [];
    public ObservableCollection<FilterChipViewModel> CategoryChips { get; } = [];
    public ObservableCollection<FilterChipViewModel> DetectorChips { get; } = [];

    public AnomaliesFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        var severities = new[] { "Critical", "High", "Medium", "Low" };
        foreach (var s in severities)
            SeverityChips.Add(new FilterChipViewModel(s));

        var categories = new[] { "Network", "TCP", "Application", "Security", "VoIP", "IoT", "Malformed" };
        foreach (var c in categories)
            CategoryChips.Add(new FilterChipViewModel(c));

        // Attack type chips matching actual anomaly Type values from detectors
        // NOTE: "Port Scan" removed - no detector creates this type
        // Added: ICMP Flood, Beaconing, TCP Retransmission (common attack types)
        var detectors = new[] { "SYN Flood", "ARP Spoofing", "ICMP Flood", "DNS Tunneling",
                                "Cryptomining", "Data Exfiltration", "Beaconing" };
        foreach (var d in detectors)
            DetectorChips.Add(new FilterChipViewModel(d));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in SeverityChips) chip.SetMode(mode);
        foreach (var chip in CategoryChips) chip.SetMode(mode);
        foreach (var chip in DetectorChips) chip.SetMode(mode);
    }

    public (List<string> Severities, List<string> Categories, List<string> Detectors) GetPendingFilters()
    {
        return (
            SeverityChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            CategoryChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            DetectorChips.Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in SeverityChips) chip.Reset();
        foreach (var chip in CategoryChips) chip.Reset();
        foreach (var chip in DetectorChips) chip.Reset();
        SearchInput = "";
    }
}
