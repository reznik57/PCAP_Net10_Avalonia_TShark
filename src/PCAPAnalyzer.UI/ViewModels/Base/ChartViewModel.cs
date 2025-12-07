using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Base class for ViewModels that display charts.
    /// Provides common chart configuration and helpers.
    /// </summary>
    [SuppressMessage("Usage", "CA2214:Do not call overridable methods in constructors",
        Justification = "InitializeAxes is a safe virtual call that only sets default axis configuration without accessing derived class state")]
    public abstract partial class ChartViewModel : ObservableObject
    {
        [ObservableProperty]
        private ObservableCollection<ISeries> _series = [];

        [ObservableProperty]
        private ObservableCollection<Axis> _xAxes = [];

        [ObservableProperty]
        private ObservableCollection<Axis> _yAxes = [];

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
        /// Common color palette for charts - delegates to ThemeColorHelper
        /// </summary>
        protected static class ChartColors
        {
            public static string Blue => ThemeColorHelper.GetChartColorHex(0);
            public static string Green => ThemeColorHelper.GetChartColorHex(1);
            public static string Amber => ThemeColorHelper.GetChartColorHex(2);
            public static string Red => ThemeColorHelper.GetChartColorHex(3);
            public static string Purple => ThemeColorHelper.GetChartColorHex(4);
            public static string Pink => ThemeColorHelper.GetChartColorHex(5);
            public static string Cyan => ThemeColorHelper.GetChartColorHex(6);
            public static string Lime => ThemeColorHelper.GetChartColorHex(7);
            public static string Orange => ThemeColorHelper.GetChartColorHex(8);
            public static string Indigo => ThemeColorHelper.GetChartColorHex(9);
            public static string Teal => ThemeColorHelper.ChartTealHex;
            public static string Gray => ThemeColorHelper.ChartGrayHex;

            public static string[] Palette => ThemeColorHelper.GetChartColorPalette();

            public static string GetColor(int index) => ThemeColorHelper.GetChartColorHex(index);
        }
    }
}
