using System;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.ViewModels.Threats;

/// <summary>
/// Manages quick filter toggles and active filter chip display.
/// Extracted from ThreatsViewModel to isolate filtering logic.
/// </summary>
public partial class ThreatsFilterViewModel : ObservableObject
{
    // ==================== QUICK FILTER TOGGLES ====================

    [ObservableProperty] private bool _isInsecureProtocolFilterActive;
    [ObservableProperty] private bool _isKnownCVEFilterActive;
    [ObservableProperty] private bool _isWeakEncryptionFilterActive;
    [ObservableProperty] private bool _isAuthIssuesFilterActive;
    [ObservableProperty] private bool _isCleartextFilterActive;

    /// <summary>
    /// Active quick filter chips displayed below the THREAT FILTERS section
    /// </summary>
    public ObservableCollection<ActiveQuickFilterChip> ActiveQuickFilterChips { get; } = new();

    /// <summary>
    /// Event fired when any filter changes
    /// </summary>
    public event Action? FiltersChanged;

    /// <summary>
    /// Returns true if any quick filter toggle is active
    /// </summary>
    public bool HasActiveQuickFilters =>
        IsInsecureProtocolFilterActive || IsKnownCVEFilterActive ||
        IsWeakEncryptionFilterActive || IsAuthIssuesFilterActive ||
        IsCleartextFilterActive;

    /// <summary>
    /// Updates the active quick filter chips collection based on enabled toggles.
    /// </summary>
    public void UpdateActiveChips()
    {
        ActiveQuickFilterChips.Clear();

        if (IsInsecureProtocolFilterActive)
        {
            ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
            {
                Emoji = "🔓",
                DisplayLabel = "Insecure Protocol",
                RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                {
                    IsInsecureProtocolFilterActive = false;
                    FiltersChanged?.Invoke();
                })
            });
        }

        if (IsKnownCVEFilterActive)
        {
            ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
            {
                Emoji = "🛡️",
                DisplayLabel = "Known CVEs",
                RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                {
                    IsKnownCVEFilterActive = false;
                    FiltersChanged?.Invoke();
                })
            });
        }

        if (IsWeakEncryptionFilterActive)
        {
            ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
            {
                Emoji = "🔐",
                DisplayLabel = "Weak Encryption",
                RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                {
                    IsWeakEncryptionFilterActive = false;
                    FiltersChanged?.Invoke();
                })
            });
        }

        if (IsAuthIssuesFilterActive)
        {
            ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
            {
                Emoji = "🔑",
                DisplayLabel = "Auth Issues",
                RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                {
                    IsAuthIssuesFilterActive = false;
                    FiltersChanged?.Invoke();
                })
            });
        }

        if (IsCleartextFilterActive)
        {
            ActiveQuickFilterChips.Add(new ActiveQuickFilterChip
            {
                Emoji = "📝",
                DisplayLabel = "Cleartext",
                RemoveCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(() =>
                {
                    IsCleartextFilterActive = false;
                    FiltersChanged?.Invoke();
                })
            });
        }

        OnPropertyChanged(nameof(ActiveQuickFilterChips));
        OnPropertyChanged(nameof(HasActiveQuickFilters));
    }

    /// <summary>
    /// Clears all quick filter toggles
    /// </summary>
    public void ClearAll()
    {
        IsInsecureProtocolFilterActive = false;
        IsKnownCVEFilterActive = false;
        IsWeakEncryptionFilterActive = false;
        IsAuthIssuesFilterActive = false;
        IsCleartextFilterActive = false;
        UpdateActiveChips();
    }

    /// <summary>
    /// Checks if a threat matches any active quick filter (OR logic)
    /// </summary>
    public bool MatchesActiveFilters(EnhancedSecurityThreat threat)
    {
        if (!HasActiveQuickFilters) return true;

        return (IsInsecureProtocolFilterActive && IsInsecureProtocolThreat(threat)) ||
               (IsKnownCVEFilterActive && IsKnownCVEThreat(threat)) ||
               (IsWeakEncryptionFilterActive && IsWeakEncryptionThreat(threat)) ||
               (IsAuthIssuesFilterActive && IsAuthIssueThreat(threat)) ||
               (IsCleartextFilterActive && IsCleartextThreat(threat));
    }

    // ==================== FILTER HELPER METHODS ====================

    /// <summary>
    /// Checks if threat is related to insecure protocol usage (HTTP, Telnet, FTP, etc.)
    /// </summary>
    public static bool IsInsecureProtocolThreat(EnhancedSecurityThreat t)
    {
        var name = t.ThreatName.ToUpperInvariant();
        var desc = t.Description.ToUpperInvariant();
        return name.Contains("INSECURE", StringComparison.Ordinal) ||
               name.Contains("UNENCRYPTED", StringComparison.Ordinal) ||
               (name.Contains("HTTP", StringComparison.Ordinal) && !name.Contains("HTTPS", StringComparison.Ordinal)) ||
               name.Contains("TELNET", StringComparison.Ordinal) ||
               (name.Contains("FTP", StringComparison.Ordinal) && !name.Contains("SFTP", StringComparison.Ordinal)) ||
               desc.Contains("INSECURE PROTOCOL", StringComparison.Ordinal) ||
               desc.Contains("CLEARTEXT PROTOCOL", StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks if threat is a known CVE vulnerability
    /// </summary>
    public static bool IsKnownCVEThreat(EnhancedSecurityThreat t)
    {
        var name = t.ThreatName.ToUpperInvariant();
        var desc = t.Description.ToUpperInvariant();
        return name.Contains("CVE-", StringComparison.Ordinal) ||
               desc.Contains("CVE-", StringComparison.Ordinal) ||
               name.Contains("VULNERABILITY", StringComparison.Ordinal) ||
               desc.Contains("KNOWN VULNERABILITY", StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks if threat is related to weak encryption
    /// </summary>
    public static bool IsWeakEncryptionThreat(EnhancedSecurityThreat t)
    {
        var name = t.ThreatName.ToUpperInvariant();
        var desc = t.Description.ToUpperInvariant();
        return (name.Contains("WEAK", StringComparison.Ordinal) &&
                (name.Contains("ENCRYPT", StringComparison.Ordinal) ||
                 name.Contains("CIPHER", StringComparison.Ordinal) ||
                 name.Contains("SSL", StringComparison.Ordinal) ||
                 name.Contains("TLS", StringComparison.Ordinal))) ||
               desc.Contains("WEAK ENCRYPTION", StringComparison.Ordinal) ||
               desc.Contains("WEAK CIPHER", StringComparison.Ordinal) ||
               name.Contains("SSL", StringComparison.Ordinal) ||
               name.Contains("TLS 1.0", StringComparison.Ordinal) ||
               name.Contains("TLS 1.1", StringComparison.Ordinal) ||
               name.Contains("RC4", StringComparison.Ordinal) ||
               name.Contains("DES", StringComparison.Ordinal) ||
               name.Contains("MD5", StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks if threat is related to authentication issues
    /// </summary>
    public static bool IsAuthIssueThreat(EnhancedSecurityThreat t)
    {
        var name = t.ThreatName.ToUpperInvariant();
        var desc = t.Description.ToUpperInvariant();
        return name.Contains("AUTH", StringComparison.Ordinal) ||
               name.Contains("LOGIN", StringComparison.Ordinal) ||
               name.Contains("PASSWORD", StringComparison.Ordinal) ||
               name.Contains("CREDENTIAL", StringComparison.Ordinal) ||
               desc.Contains("AUTHENTICATION", StringComparison.Ordinal) ||
               desc.Contains("UNAUTHORIZED", StringComparison.Ordinal) ||
               desc.Contains("ACCESS CONTROL", StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks if threat involves cleartext/unencrypted data transmission
    /// </summary>
    public static bool IsCleartextThreat(EnhancedSecurityThreat t)
    {
        var name = t.ThreatName.ToUpperInvariant();
        var desc = t.Description.ToUpperInvariant();
        return name.Contains("CLEARTEXT", StringComparison.Ordinal) ||
               name.Contains("PLAIN TEXT", StringComparison.Ordinal) ||
               name.Contains("PLAINTEXT", StringComparison.Ordinal) ||
               desc.Contains("CLEARTEXT", StringComparison.Ordinal) ||
               desc.Contains("UNENCRYPTED DATA", StringComparison.Ordinal) ||
               desc.Contains("SENSITIVE DATA EXPOSED", StringComparison.Ordinal);
    }
}

/// <summary>
/// Represents an active quick filter chip with emoji, label, and remove command.
/// </summary>
public class ActiveQuickFilterChip : ObservableObject
{
    public string Emoji { get; set; } = "";
    public string DisplayLabel { get; set; } = "";
    public IRelayCommand? RemoveCommand { get; set; }
}
