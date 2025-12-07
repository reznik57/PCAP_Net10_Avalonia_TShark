using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class VoiceQoSFilterTabViewModel : ObservableObject
{
    [ObservableProperty] private string _jitterThresholdInput = "";
    [ObservableProperty] private string _latencyThresholdInput = "";

    public ObservableCollection<FilterChipViewModel> CodecChips { get; } = [];
    public ObservableCollection<FilterChipViewModel> QualityChips { get; } = [];
    public ObservableCollection<FilterChipViewModel> IssueChips { get; } = [];

    public VoiceQoSFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        var codecs = new[] { "G.711", "G.729", "Opus", "H.264", "VP8", "VP9" };
        foreach (var c in codecs)
            CodecChips.Add(new FilterChipViewModel(c));

        var qualities = new[] { "Poor", "Fair", "Good", "Excellent" };
        foreach (var q in qualities)
            QualityChips.Add(new FilterChipViewModel(q));

        var issues = new[] { "High Jitter", "High Latency", "Packet Loss" };
        foreach (var i in issues)
            IssueChips.Add(new FilterChipViewModel(i));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in CodecChips) chip.SetMode(mode);
        foreach (var chip in QualityChips) chip.SetMode(mode);
        foreach (var chip in IssueChips) chip.SetMode(mode);
    }

    public (List<string> Codecs, List<string> Qualities, List<string> Issues) GetPendingFilters()
    {
        return (
            CodecChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            QualityChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            IssueChips.Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in CodecChips) chip.Reset();
        foreach (var chip in QualityChips) chip.Reset();
        foreach (var chip in IssueChips) chip.Reset();
        JitterThresholdInput = "";
        LatencyThresholdInput = "";
    }
}
