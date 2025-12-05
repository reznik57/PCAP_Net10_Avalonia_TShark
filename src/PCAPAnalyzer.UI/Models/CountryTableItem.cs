using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Models
{
    public partial class CountryTableItem : ObservableObject
    {
        [ObservableProperty] private int _rank;
        [ObservableProperty] private string _countryCode = "";
        [ObservableProperty] private string _countryName = "";
        [ObservableProperty] private string _continent = "";
        [ObservableProperty] private long _totalPackets;
        [ObservableProperty] private long _totalBytes;
        [ObservableProperty] private double _packetPercentage;
        [ObservableProperty] private double _bytePercentage;
        [ObservableProperty] private bool _isHighRisk;
        [ObservableProperty] private CountryTableContext _context = CountryTableContext.Aggregated;

        /// <summary>
        /// Timeline data for sparkline visualization.
        /// Contains packet counts bucketed over time (20 buckets across capture duration).
        /// </summary>
        [ObservableProperty] private IReadOnlyList<double>? _timelineBuckets;

        // Additional properties for display
        public long PacketCount => TotalPackets;
        public long ByteCount => TotalBytes;

        public string PacketsFormatted => $"{TotalPackets:N0}";
        public string BytesFormatted => NumberFormatter.FormatBytes(TotalBytes);

        // Display country code with full name
        private bool _suppressNameUpdate;

        public string CountryDisplay
        {
            get
            {
                var displayCode = CountryNameHelper.GetDisplayCode(CountryCode);
                var displayName = CountryNameHelper.GetDisplayName(CountryCode, CountryName);

                if (string.IsNullOrWhiteSpace(displayName) ||
                    string.Equals(displayName, displayCode, StringComparison.OrdinalIgnoreCase))
                {
                    return displayCode;
                }

                return $"{displayCode} {displayName}";
            }
        }

        public CountryTableItem()
        {
        }

        public CountryTableItem(string code, string name, string continent, long packets, long bytes, double packetPct, double bytePct, bool highRisk = false)
        {
            CountryCode = code;
            CountryName = name;
            Continent = continent;
            TotalPackets = packets;
            TotalBytes = bytes;
            PacketPercentage = packetPct;
            BytePercentage = bytePct;
            IsHighRisk = highRisk;
            EnsureResolvedCountryName();
        }

        partial void OnCountryCodeChanged(string value)
        {
            EnsureResolvedCountryName();
            OnPropertyChanged(nameof(CountryDisplay));
        }

        partial void OnCountryNameChanged(string value)
        {
            if (_suppressNameUpdate)
            {
                return;
            }

            var resolved = CountryNameHelper.GetDisplayName(CountryCode, value);
            if (!string.Equals(resolved, value, StringComparison.Ordinal))
            {
                try
                {
                    _suppressNameUpdate = true;
                    CountryName = resolved;
                }
                finally
                {
                    _suppressNameUpdate = false;
                }
            }

            OnPropertyChanged(nameof(CountryDisplay));
        }

        private void EnsureResolvedCountryName()
        {
            if (_suppressNameUpdate)
            {
                return;
            }

            var resolved = CountryNameHelper.GetDisplayName(CountryCode, CountryName);
            if (!string.IsNullOrWhiteSpace(resolved) && !string.Equals(resolved, CountryName, StringComparison.Ordinal))
            {
                try
                {
                    _suppressNameUpdate = true;
                    CountryName = resolved;
                }
                finally
                {
                    _suppressNameUpdate = false;
                }
            }

            OnPropertyChanged(nameof(CountryDisplay));
        }
    }

    public enum CountryTableContext
    {
        Aggregated,
        SourcePackets,
        SourceBytes,
        DestinationPackets,
        DestinationBytes,
        CrossBorderFlow
    }
}
