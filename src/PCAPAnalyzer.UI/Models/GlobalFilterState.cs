using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Global filter state singleton. Stores Include/Exclude criteria.
/// Version increments on every change for lazy per-tab evaluation.
/// </summary>
public partial class GlobalFilterState : ObservableObject
{
    [ObservableProperty] private FilterMode _currentMode = FilterMode.Include;
    [ObservableProperty] private int _version;

    public FilterCriteria IncludeFilters { get; } = new();
    public FilterCriteria ExcludeFilters { get; } = new();

    public bool HasActiveFilters => IncludeFilters.HasAny || ExcludeFilters.HasAny;

    public event Action? OnFilterChanged;

    public void AddIncludeProtocol(string protocol)
    {
        IncludeFilters.Protocols.Add(protocol);
        IncrementVersion();
    }

    public void AddExcludeProtocol(string protocol)
    {
        ExcludeFilters.Protocols.Add(protocol);
        IncrementVersion();
    }

    public void AddIncludeIP(string ip)
    {
        IncludeFilters.IPs.Add(ip);
        IncrementVersion();
    }

    public void AddExcludeIP(string ip)
    {
        ExcludeFilters.IPs.Add(ip);
        IncrementVersion();
    }

    public void AddIncludePort(string port)
    {
        IncludeFilters.Ports.Add(port);
        IncrementVersion();
    }

    public void AddExcludePort(string port)
    {
        ExcludeFilters.Ports.Add(port);
        IncrementVersion();
    }

    public void RemoveIncludeFilter(string value, FilterCategory category)
    {
        var removed = category switch
        {
            FilterCategory.Protocol => IncludeFilters.Protocols.Remove(value),
            FilterCategory.IP => IncludeFilters.IPs.Remove(value),
            FilterCategory.Port => IncludeFilters.Ports.Remove(value),
            FilterCategory.QuickFilter => IncludeFilters.QuickFilters.Remove(value),
            FilterCategory.Severity => IncludeFilters.Severities.Remove(value),
            FilterCategory.ThreatCategory => IncludeFilters.ThreatCategories.Remove(value),
            FilterCategory.TlsVersion => IncludeFilters.TlsVersions.Remove(value),
            FilterCategory.Country => IncludeFilters.Countries.Remove(value),
            _ => false
        };
        if (removed) IncrementVersion();
    }

    public void RemoveExcludeFilter(string value, FilterCategory category)
    {
        var removed = category switch
        {
            FilterCategory.Protocol => ExcludeFilters.Protocols.Remove(value),
            FilterCategory.IP => ExcludeFilters.IPs.Remove(value),
            FilterCategory.Port => ExcludeFilters.Ports.Remove(value),
            FilterCategory.QuickFilter => ExcludeFilters.QuickFilters.Remove(value),
            FilterCategory.Severity => ExcludeFilters.Severities.Remove(value),
            FilterCategory.ThreatCategory => ExcludeFilters.ThreatCategories.Remove(value),
            FilterCategory.TlsVersion => ExcludeFilters.TlsVersions.Remove(value),
            FilterCategory.Country => ExcludeFilters.Countries.Remove(value),
            _ => false
        };
        if (removed) IncrementVersion();
    }

    public void Clear()
    {
        IncludeFilters.Clear();
        ExcludeFilters.Clear();
        IncrementVersion();
    }

    private void IncrementVersion()
    {
        Version++;
        OnFilterChanged?.Invoke();
    }
}

public enum FilterMode { Include, Exclude }

public enum FilterCategory { Protocol, IP, Port, QuickFilter, Severity, ThreatCategory, TlsVersion, Country }

public class FilterCriteria
{
    public ObservableCollection<string> Protocols { get; } = new();
    public ObservableCollection<string> IPs { get; } = new();
    public ObservableCollection<string> Ports { get; } = new();
    public ObservableCollection<string> QuickFilters { get; } = new();
    public ObservableCollection<string> Severities { get; } = new();
    public ObservableCollection<string> ThreatCategories { get; } = new();
    public ObservableCollection<string> TlsVersions { get; } = new();
    public ObservableCollection<string> Countries { get; } = new();

    public bool HasAny => Protocols.Count > 0 || IPs.Count > 0 || Ports.Count > 0 ||
                          QuickFilters.Count > 0 || Severities.Count > 0 ||
                          ThreatCategories.Count > 0 || TlsVersions.Count > 0 ||
                          Countries.Count > 0;

    public void Clear()
    {
        Protocols.Clear();
        IPs.Clear();
        Ports.Clear();
        QuickFilters.Clear();
        Severities.Clear();
        ThreatCategories.Clear();
        TlsVersions.Clear();
        Countries.Clear();
    }
}
