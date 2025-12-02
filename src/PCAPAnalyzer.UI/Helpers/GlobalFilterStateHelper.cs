using System;
using System.Collections.Generic;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.Helpers;

/// <summary>
/// Helper class to extract filter criteria from GlobalFilterState.
/// Reduces code duplication across ViewModels by centralizing collection logic.
/// </summary>
public static class GlobalFilterStateHelper
{
    /// <summary>
    /// Collects threat criteria (severities, categories) from GlobalFilterState.
    /// </summary>
    /// <returns>Tuple of (includeSeverities, includeCategories, excludeSeverities, excludeCategories)</returns>
    public static (HashSet<string> IncludeSeverities, HashSet<string> IncludeCategories,
                   HashSet<string> ExcludeSeverities, HashSet<string> ExcludeCategories)
        CollectThreatCriteria(GlobalFilterState state)
    {
        var includeSeverities = new HashSet<string>(state.IncludeFilters.Severities, StringComparer.OrdinalIgnoreCase);
        var includeCategories = new HashSet<string>(state.IncludeFilters.ThreatCategories, StringComparer.OrdinalIgnoreCase);

        foreach (var group in state.IncludeGroups)
        {
            var criteria = group.GetThreatCriteria();
            if (criteria.HasValue)
            {
                if (criteria.Value.Severities != null)
                    foreach (var s in criteria.Value.Severities)
                        includeSeverities.Add(s);
                if (criteria.Value.Categories != null)
                    foreach (var c in criteria.Value.Categories)
                        includeCategories.Add(c);
            }
        }

        var excludeSeverities = new HashSet<string>(state.ExcludeFilters.Severities, StringComparer.OrdinalIgnoreCase);
        var excludeCategories = new HashSet<string>(state.ExcludeFilters.ThreatCategories, StringComparer.OrdinalIgnoreCase);

        foreach (var group in state.ExcludeGroups)
        {
            var criteria = group.GetThreatCriteria();
            if (criteria.HasValue)
            {
                if (criteria.Value.Severities != null)
                    foreach (var s in criteria.Value.Severities)
                        excludeSeverities.Add(s);
                if (criteria.Value.Categories != null)
                    foreach (var c in criteria.Value.Categories)
                        excludeCategories.Add(c);
            }
        }

        return (includeSeverities, includeCategories, excludeSeverities, excludeCategories);
    }

    /// <summary>
    /// Collects VoiceQoS criteria (codecs, quality levels) from GlobalFilterState.
    /// </summary>
    /// <returns>Tuple of (includeCodecs, includeQualities, excludeCodecs, excludeQualities)</returns>
    public static (HashSet<string> IncludeCodecs, HashSet<string> IncludeQualities,
                   HashSet<string> ExcludeCodecs, HashSet<string> ExcludeQualities)
        CollectVoiceQoSCriteria(GlobalFilterState state)
    {
        var includeCodecs = new HashSet<string>(state.IncludeFilters.Codecs, StringComparer.OrdinalIgnoreCase);
        var includeQualities = new HashSet<string>(state.IncludeFilters.QualityLevels, StringComparer.OrdinalIgnoreCase);

        foreach (var group in state.IncludeGroups)
        {
            var criteria = group.GetVoiceQoSCriteria();
            if (criteria.HasValue)
            {
                if (criteria.Value.Codecs != null)
                    foreach (var c in criteria.Value.Codecs)
                        includeCodecs.Add(c);
                if (criteria.Value.Qualities != null)
                    foreach (var q in criteria.Value.Qualities)
                        includeQualities.Add(q);
            }
        }

        var excludeCodecs = new HashSet<string>(state.ExcludeFilters.Codecs, StringComparer.OrdinalIgnoreCase);
        var excludeQualities = new HashSet<string>(state.ExcludeFilters.QualityLevels, StringComparer.OrdinalIgnoreCase);

        foreach (var group in state.ExcludeGroups)
        {
            var criteria = group.GetVoiceQoSCriteria();
            if (criteria.HasValue)
            {
                if (criteria.Value.Codecs != null)
                    foreach (var c in criteria.Value.Codecs)
                        excludeCodecs.Add(c);
                if (criteria.Value.Qualities != null)
                    foreach (var q in criteria.Value.Qualities)
                        excludeQualities.Add(q);
            }
        }

        return (includeCodecs, includeQualities, excludeCodecs, excludeQualities);
    }

    /// <summary>
    /// Collects country criteria (countries, regions) from GlobalFilterState.
    /// </summary>
    /// <returns>Tuple of (includeCountries, includeRegions, excludeCountries, excludeRegions)</returns>
    public static (HashSet<string> IncludeCountries, HashSet<string> IncludeRegions,
                   HashSet<string> ExcludeCountries, HashSet<string> ExcludeRegions)
        CollectCountryCriteria(GlobalFilterState state)
    {
        var includeCountries = new HashSet<string>(state.IncludeFilters.Countries, StringComparer.OrdinalIgnoreCase);
        var includeRegions = new HashSet<string>(state.IncludeFilters.Regions, StringComparer.OrdinalIgnoreCase);

        foreach (var group in state.IncludeGroups)
        {
            var criteria = group.GetCountryCriteria();
            if (criteria.HasValue)
            {
                if (criteria.Value.Countries != null)
                    foreach (var c in criteria.Value.Countries)
                        includeCountries.Add(c);
                if (criteria.Value.Regions != null)
                    foreach (var r in criteria.Value.Regions)
                        includeRegions.Add(r);
            }
        }

        var excludeCountries = new HashSet<string>(state.ExcludeFilters.Countries, StringComparer.OrdinalIgnoreCase);
        var excludeRegions = new HashSet<string>(state.ExcludeFilters.Regions, StringComparer.OrdinalIgnoreCase);

        foreach (var group in state.ExcludeGroups)
        {
            var criteria = group.GetCountryCriteria();
            if (criteria.HasValue)
            {
                if (criteria.Value.Countries != null)
                    foreach (var c in criteria.Value.Countries)
                        excludeCountries.Add(c);
                if (criteria.Value.Regions != null)
                    foreach (var r in criteria.Value.Regions)
                        excludeRegions.Add(r);
            }
        }

        return (includeCountries, includeRegions, excludeCountries, excludeRegions);
    }
}
