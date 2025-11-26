using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Base class for ViewModels that integrate with the global filter service.
    /// Automatically subscribes to filter changes and provides update hook.
    /// </summary>
    public abstract partial class FilterableViewModel : ObservableObject, IDisposable
    {
        protected IGlobalFilterService FilterService { get; }
        private bool _isDisposed;

        [ObservableProperty]
        private bool _isFilterActive;

        [ObservableProperty]
        private string _filterSummary = "No filter applied";

        protected FilterableViewModel(IGlobalFilterService filterService)
        {
            FilterService = filterService ?? throw new ArgumentNullException(nameof(filterService));
            FilterService.FilterChanged += OnFilterServiceChanged;

            // Initialize with current filter state
            IsFilterActive = FilterService.CurrentFilter != null && !FilterService.CurrentFilter.IsEmpty;
            UpdateFilterSummary();
        }

        private async void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
        {
            IsFilterActive = e.Filter != null && !e.Filter.IsEmpty;
            UpdateFilterSummary();
            await OnFilterChangedAsync(e.Filter);
        }

        /// <summary>
        /// Override this method to handle filter changes.
        /// Called automatically when the global filter changes.
        /// </summary>
        protected abstract Task OnFilterChangedAsync(PacketFilter? filter);

        /// <summary>
        /// Update the filter summary text
        /// </summary>
        private void UpdateFilterSummary()
        {
            var filter = FilterService.CurrentFilter;
            if (filter == null || filter.IsEmpty)
            {
                FilterSummary = "No filter applied";
                return;
            }

            var parts = new List<string>();

            if (filter.SourceIPs?.Count > 0)
                parts.Add($"Source IPs: {filter.SourceIPs.Count}");

            if (filter.DestinationIPs?.Count > 0)
                parts.Add($"Dest IPs: {filter.DestinationIPs.Count}");

            if (filter.Protocols?.Count > 0)
                parts.Add($"Protocols: {filter.Protocols.Count}");

            if (filter.Ports?.Count > 0)
                parts.Add($"Ports: {filter.Ports.Count}");

            if (filter.ShowOnlyRFC1918.HasValue && filter.ShowOnlyRFC1918.Value)
                parts.Add("RFC1918 only");

            if (filter.ShowOnlyPublicIPs.HasValue && filter.ShowOnlyPublicIPs.Value)
                parts.Add("Public IPs only");

            FilterSummary = parts.Count > 0
                ? string.Join(" | ", parts)
                : "Custom filter active";
        }

        /// <summary>
        /// Get the current filter
        /// </summary>
        protected PacketFilter? GetCurrentFilter() => FilterService.CurrentFilter;

        /// <summary>
        /// Check if a specific filter type is active
        /// </summary>
        protected bool HasSourceIPFilter() =>
            FilterService.CurrentFilter?.SourceIPs?.Count > 0;

        protected bool HasDestinationIPFilter() =>
            FilterService.CurrentFilter?.DestinationIPs?.Count > 0;

        protected bool HasProtocolFilter() =>
            FilterService.CurrentFilter?.Protocols?.Count > 0;

        protected bool HasPortFilter() =>
            FilterService.CurrentFilter?.Ports?.Count > 0;

        public virtual void Dispose()
        {
            if (_isDisposed) return;

            FilterService.FilterChanged -= OnFilterServiceChanged;
            _isDisposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
