using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Filter preset commands for DashboardViewModel.
/// </summary>
public partial class DashboardViewModel
{
    private async Task LoadPresetsAsync()
    {
        if (_filterPresetService is null)
        {
            DebugLogger.Log("[DashboardViewModel] FilterPresetService not available");
            return;
        }

        try
        {
            IsLoadingPresets = true;
            var presets = await _filterPresetService.GetAllPresetsAsync();

            await _dispatcher.InvokeAsync(() =>
            {
                AvailablePresets.Clear();
                foreach (var preset in presets)
                {
                    AvailablePresets.Add(preset);
                }
            });

            DebugLogger.Log($"[DashboardViewModel] Loaded {presets.Count} filter presets");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error loading presets: {ex.Message}");
        }
        finally
        {
            IsLoadingPresets = false;
        }
    }

    [RelayCommand]
    private async Task ApplyPresetAsync()
    {
        if (SelectedPreset is null || _filterPresetService is null)
            return;

        try
        {
            DebugLogger.Log($"[DashboardViewModel] Applying preset: {SelectedPreset.Name}");
            _filterPresetService.ApplyPreset(SelectedPreset, this);
            await ApplyFiltersAsync();

            ExportStatusMessage = $"Applied preset: {SelectedPreset.Name}";
            ExportStatusColor = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error applying preset: {ex.Message}");
            ExportStatusMessage = $"Error applying preset: {ex.Message}";
            ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
            _ = AutoClearExportStatusAsync();
        }
    }

    [RelayCommand]
    private async Task SaveCurrentAsPresetAsync(string? presetName)
    {
        if (_filterPresetService is null)
        {
            ExportStatusMessage = "Preset service not available";
            ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
            _ = AutoClearExportStatusAsync();
            return;
        }

        if (string.IsNullOrWhiteSpace(presetName))
        {
            ExportStatusMessage = "Preset name is required";
            ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
            _ = AutoClearExportStatusAsync();
            return;
        }

        try
        {
            var preset = _filterPresetService.CreateFromViewModel(
                presetName,
                $"Custom preset created on {DateTime.Now:yyyy-MM-dd HH:mm}",
                this);

            var success = await _filterPresetService.SavePresetAsync(preset);

            if (success)
            {
                await LoadPresetsAsync();
                ExportStatusMessage = $"Saved preset: {presetName}";
                ExportStatusColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981");
                DebugLogger.Log($"[DashboardViewModel] Saved new preset: {presetName}");
            }
            else
            {
                ExportStatusMessage = $"Cannot save preset: {presetName} (conflicts with built-in)";
                ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
                DebugLogger.Log($"[DashboardViewModel] Failed to save preset: {presetName}");
            }

            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error saving preset: {ex.Message}");
            ExportStatusMessage = $"Error saving preset: {ex.Message}";
            ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
            _ = AutoClearExportStatusAsync();
        }
    }

    [RelayCommand]
    private async Task DeletePresetAsync(FilterPreset? preset)
    {
        if (preset is null || _filterPresetService is null)
            return;

        if (preset.IsBuiltIn)
        {
            ExportStatusMessage = "Cannot delete built-in presets";
            ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
            _ = AutoClearExportStatusAsync();
            return;
        }

        try
        {
            var success = await _filterPresetService.DeletePresetAsync(preset.Name);

            if (success)
            {
                await LoadPresetsAsync();
                if (SelectedPreset?.Name == preset.Name)
                    SelectedPreset = null;

                ExportStatusMessage = $"Deleted preset: {preset.Name}";
                ExportStatusColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981");
                DebugLogger.Log($"[DashboardViewModel] Deleted preset: {preset.Name}");
            }
            else
            {
                ExportStatusMessage = $"Failed to delete preset: {preset.Name}";
                ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
            }

            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error deleting preset: {ex.Message}");
            ExportStatusMessage = $"Error deleting preset: {ex.Message}";
            ExportStatusColor = ThemeColorHelper.GetColorHex("ColorDanger", "#DC2626");
            _ = AutoClearExportStatusAsync();
        }
    }
}
