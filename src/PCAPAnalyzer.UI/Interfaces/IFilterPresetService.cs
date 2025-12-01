using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Interfaces;

/// <summary>
/// Service for managing Dashboard filter presets.
/// Provides save/load/delete operations with built-in presets support.
/// </summary>
public interface IFilterPresetService
{
    /// <summary>
    /// Get all available presets (built-in + user-defined)
    /// </summary>
    Task<IReadOnlyList<FilterPreset>> GetAllPresetsAsync();

    /// <summary>
    /// Save a new or updated preset
    /// </summary>
    /// <param name="preset">The preset to save</param>
    /// <returns>True if saved successfully, false if name conflicts with built-in</returns>
    Task<bool> SavePresetAsync(FilterPreset preset);

    /// <summary>
    /// Delete a user-defined preset (cannot delete built-ins)
    /// </summary>
    /// <param name="name">Name of the preset to delete</param>
    /// <returns>True if deleted, false if not found or is built-in</returns>
    Task<bool> DeletePresetAsync(string name);

    /// <summary>
    /// Get a specific preset by name
    /// </summary>
    Task<FilterPreset?> GetPresetAsync(string name);

    /// <summary>
    /// Apply a preset to a DashboardViewModel
    /// </summary>
    /// <param name="preset">The preset to apply</param>
    /// <param name="viewModel">The DashboardViewModel to update</param>
    void ApplyPreset(FilterPreset preset, DashboardViewModel viewModel);

    /// <summary>
    /// Create a preset from current DashboardViewModel filter state
    /// </summary>
    /// <param name="name">Name for the new preset</param>
    /// <param name="description">Description of what the preset does</param>
    /// <param name="viewModel">The DashboardViewModel to capture state from</param>
    FilterPreset CreateFromViewModel(string name, string description, DashboardViewModel viewModel);

    /// <summary>
    /// Get built-in presets
    /// </summary>
    IReadOnlyList<FilterPreset> GetBuiltInPresets();
}
