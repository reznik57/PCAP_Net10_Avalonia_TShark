using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Filter tab ViewModel for Host Inventory page.
/// Provides filters for OS types, device types, and host roles.
/// </summary>
public partial class HostInventoryFilterTabViewModel : ObservableObject
{
    public ObservableCollection<FilterChipViewModel> OsTypeChips { get; } = [];
    public ObservableCollection<FilterChipViewModel> DeviceTypeChips { get; } = [];
    public ObservableCollection<FilterChipViewModel> HostRoleChips { get; } = [];

    public HostInventoryFilterTabViewModel()
    {
        InitializeChips();
    }

    private void InitializeChips()
    {
        // OS Types for fingerprinting
        var osTypes = new[] { "Windows", "Linux", "macOS", "iOS", "Android", "Unknown" };
        foreach (var os in osTypes)
            OsTypeChips.Add(new FilterChipViewModel(os));

        // Device Types
        var deviceTypes = new[] { "Server", "Workstation", "Mobile", "IoT", "Network", "Printer" };
        foreach (var dt in deviceTypes)
            DeviceTypeChips.Add(new FilterChipViewModel(dt));

        // Host Roles
        var hostRoles = new[] { "Client", "Server", "Gateway", "DNS", "DHCP", "Internal", "External" };
        foreach (var role in hostRoles)
            HostRoleChips.Add(new FilterChipViewModel(role));
    }

    public void SetMode(FilterChipMode mode)
    {
        foreach (var chip in OsTypeChips) chip.SetMode(mode);
        foreach (var chip in DeviceTypeChips) chip.SetMode(mode);
        foreach (var chip in HostRoleChips) chip.SetMode(mode);
    }

    public (List<string> OsTypes, List<string> DeviceTypes, List<string> HostRoles) GetPendingFilters()
    {
        return (
            OsTypeChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            DeviceTypeChips.Where(c => c.IsSelected).Select(c => c.Name).ToList(),
            HostRoleChips.Where(c => c.IsSelected).Select(c => c.Name).ToList()
        );
    }

    public void Reset()
    {
        foreach (var chip in OsTypeChips) chip.Reset();
        foreach (var chip in DeviceTypeChips) chip.Reset();
        foreach (var chip in HostRoleChips) chip.Reset();
    }
}
