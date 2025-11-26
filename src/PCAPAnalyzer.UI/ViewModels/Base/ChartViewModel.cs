using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Base class for ViewModels that display charts.
    /// Provides common chart configuration and helpers.
    /// </summary>
    public abstract partial class ChartViewModel : ObservableObject
    {
        [ObservableProperty]
        private ObservableCollection<ISeries> _series = new();

        [ObservableProperty]
        private ObservableCollection<Axis> _xAxes = new();

        [ObservableProperty]
        private ObservableCollection<Axis> _yAxes = new();

        [ObservableProperty]
        private string _title = string.Empty;

        [ObservableProperty]
        private bool _isLoading;

        [ObservableProperty]
        private bool _hasData;

        [ObservableProperty]
        private string _noDataMessage = "No data available";

        protected ChartViewModel()
        {
            InitializeAxes();
        }

        /// <summary>
        /// Initialize default axes - override for custom configuration
        /// </summary>
        protected virtual void InitializeAxes()
        {
            XAxes = new ObservableCollection<Axis>
            {
                new Axis
                {
                    Name = "X Axis",
                    NamePadding = new LiveChartsCore.Drawing.Padding(0, 5),
                }
            };

            YAxes = new ObservableCollection<Axis>
            {
                new Axis
                {
                    Name = "Y Axis",
                    NamePadding = new LiveChartsCore.Drawing.Padding(5, 0),
                }
            };
        }

        /// <summary>
        /// Update chart data - call after modifying Series
        /// </summary>
        protected virtual void UpdateChart()
        {
            HasData = Series.Count > 0;
        }

        /// <summary>
        /// Clear all chart data
        /// </summary>
        protected virtual void ClearChart()
        {
            Series.Clear();
            HasData = false;
        }

        /// <summary>
        /// Common color palette for charts
        /// </summary>
        protected static class ChartColors
        {
            public const string Blue = "#3B82F6";
            public const string Green = "#10B981";
            public const string Amber = "#F59E0B";
            public const string Purple = "#8B5CF6";
            public const string Pink = "#EC4899";
            public const string Teal = "#14B8A6";
            public const string Orange = "#F97316";
            public const string Red = "#EF4444";
            public const string Indigo = "#6366F1";
            public const string Gray = "#6B7280";

            public static readonly string[] Palette = new[]
            {
                Blue, Green, Purple, Pink, Teal, Orange, Red, Indigo, Amber, Gray
            };

            public static string GetColor(int index)
            {
                return Palette[index % Palette.Length];
            }
        }
    }
}
