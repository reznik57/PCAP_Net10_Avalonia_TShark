using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class VoiceQoSFilterTabViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;

    [ObservableProperty] private string _jitterThresholdInput = "";
    [ObservableProperty] private string _latencyThresholdInput = "";

    // Observable chip collections with state tracking
    public ObservableCollection<FilterChipViewModel> CodecChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> QualityChips { get; } = new();
    public ObservableCollection<FilterChipViewModel> IssueChips { get; } = new();

    public VoiceQoSFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
        InitializeChips();
    }

    private void InitializeChips()
    {
        // Codec chips
        var codecs = new[] { "G.711", "G.729", "Opus", "H.264", "VP8", "VP9" };
        foreach (var c in codecs)
            CodecChips.Add(new FilterChipViewModel(c, _filterState, FilterCategory.Codec));

        // Quality chips
        var qualities = new[] { "Poor", "Fair", "Good", "Excellent" };
        foreach (var q in qualities)
            QualityChips.Add(new FilterChipViewModel(q, _filterState, FilterCategory.QualityLevel));

        // Issue chips
        var issues = new[] { "High Jitter", "High Latency", "Packet Loss" };
        foreach (var i in issues)
            IssueChips.Add(new FilterChipViewModel(i, _filterState, FilterCategory.VoipIssue));
    }

    [RelayCommand]
    private void SetJitterThreshold()
    {
        if (string.IsNullOrWhiteSpace(JitterThresholdInput)) return;

        _filterState.SetJitterThreshold(JitterThresholdInput.Trim());
        JitterThresholdInput = "";
    }

    [RelayCommand]
    private void SetLatencyThreshold()
    {
        if (string.IsNullOrWhiteSpace(LatencyThresholdInput)) return;

        _filterState.SetLatencyThreshold(LatencyThresholdInput.Trim());
        LatencyThresholdInput = "";
    }
}
