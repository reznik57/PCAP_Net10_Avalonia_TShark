using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for displaying an insecure port detection item.
/// </summary>
public class InsecurePortItemViewModel : ObservableObject
{
    private static readonly string DefaultRiskColor = ThemeColorHelper.GetColorHex("TextMuted", "#6B7280");

    public int Port { get; set; }
    public string ServiceName { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string RiskLevel { get; set; } = "";
    public string RiskColor { get; set; } = DefaultRiskColor;
    public bool IsEncrypted { get; set; }
    public int DetectedPackets { get; set; }
    public bool IsActive { get; set; }
    public string RecommendedAlternative { get; set; } = "";
    public string SecurityNotes { get; set; } = "";
    public bool RequiresAction { get; set; }

    public string StatusIcon => IsActive ? "⚠️" : "✓";
    public string StatusText => IsActive ? "DETECTED" : "Not Detected";
    public string EncryptionIcon => IsEncrypted ? "🔒" : "🔓";
    public string EncryptionText => IsEncrypted ? "Encrypted" : "UNENCRYPTED";
}
