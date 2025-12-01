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

    // Predefined codec chips
    public static readonly string[] CodecChips =
        { "G.711", "G.729", "Opus", "H.264", "VP8", "VP9" };

    public static readonly string[] QualityChips =
        { "Poor", "Fair", "Good", "Excellent" };

    public static readonly string[] IssueChips =
        { "High Jitter", "High Latency", "Packet Loss" };

    public VoiceQoSFilterTabViewModel(GlobalFilterState filterState)
    {
        _filterState = filterState;
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

    [RelayCommand]
    private void ToggleCodec(string codec)
    {
        // Check if already in include list
        if (_filterState.IncludeFilters.Codecs.Contains(codec))
        {
            _filterState.RemoveIncludeFilter(codec, FilterCategory.Codec);
            return;
        }

        // Check if already in exclude list
        if (_filterState.ExcludeFilters.Codecs.Contains(codec))
        {
            _filterState.RemoveExcludeFilter(codec, FilterCategory.Codec);
            return;
        }

        // Add based on current mode
        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeCodec(codec);
        else
            _filterState.AddExcludeCodec(codec);
    }

    [RelayCommand]
    private void ToggleQualityLevel(string quality)
    {
        if (_filterState.IncludeFilters.QualityLevels.Contains(quality))
        {
            _filterState.RemoveIncludeFilter(quality, FilterCategory.QualityLevel);
            return;
        }

        if (_filterState.ExcludeFilters.QualityLevels.Contains(quality))
        {
            _filterState.RemoveExcludeFilter(quality, FilterCategory.QualityLevel);
            return;
        }

        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeQualityLevel(quality);
        else
            _filterState.AddExcludeQualityLevel(quality);
    }

    [RelayCommand]
    private void ToggleVoipIssue(string issue)
    {
        if (_filterState.IncludeFilters.VoipIssues.Contains(issue))
        {
            _filterState.RemoveIncludeFilter(issue, FilterCategory.VoipIssue);
            return;
        }

        if (_filterState.ExcludeFilters.VoipIssues.Contains(issue))
        {
            _filterState.RemoveExcludeFilter(issue, FilterCategory.VoipIssue);
            return;
        }

        if (_filterState.CurrentMode == FilterMode.Include)
            _filterState.AddIncludeVoipIssue(issue);
        else
            _filterState.AddExcludeVoipIssue(issue);
    }

    // Helper to check chip state for UI styling
    public ChipState GetCodecChipState(string codec)
    {
        if (_filterState.IncludeFilters.Codecs.Contains(codec))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.Codecs.Contains(codec))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }

    public ChipState GetQualityChipState(string quality)
    {
        if (_filterState.IncludeFilters.QualityLevels.Contains(quality))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.QualityLevels.Contains(quality))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }

    public ChipState GetVoipIssueChipState(string issue)
    {
        if (_filterState.IncludeFilters.VoipIssues.Contains(issue))
            return ChipState.Included;
        if (_filterState.ExcludeFilters.VoipIssues.Contains(issue))
            return ChipState.Excluded;
        return ChipState.Inactive;
    }
}
