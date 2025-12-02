using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class GeneralFilterTabViewModel : ObservableObject
{
    // NOTE: IP/Port inputs moved to UnifiedFilterPanelViewModel (shared across all tabs)

    public ObservableCollection<FilterChipViewModel> ProtocolChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> SecurityChips { get; } = new();

    public GeneralFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        var protocols = new[] { "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "TLS", "SSH", "FTP", "SMTP" };
        foreach (var p in protocols)
            ProtocolChips.Add(new FilterChipViewModel(p));

        var security = new[] { "Insecure", "Anomalies", "Suspicious", "TCP Issues" };
        foreach (var s in security)
            SecurityChips.Add(new FilterChipViewModel(s));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in ProtocolChips) chip.SetMode(mode);
        foreach (var chip in SecurityChips) chip.SetMode(mode);
    }

    public (List<string> Protocols, List<string> QuickFilters) GetPendingFilters()
    {
        return (
            ProtocolChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            SecurityChips.Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in ProtocolChips) chip.Reset();
        foreach (var chip in SecurityChips) chip.Reset();
    }
}
