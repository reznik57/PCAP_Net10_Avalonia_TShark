namespace PCAPAnalyzer.UI.Constants;

/// <summary>
/// View mode constants for traffic direction filtering.
/// </summary>
public static class ViewModes
{
    public const string Combined = "Combined";
    public const string Source = "Source";
    public const string Destination = "Destination";
}

/// <summary>
/// Metric type constants for data aggregation.
/// </summary>
public static class MetricTypes
{
    public const string Packets = "Packets";
    public const string Bytes = "Bytes";
    public const string Flows = "Flows";
    public const string Connections = "Connections";
}

/// <summary>
/// Filter mode constants for traffic filtering.
/// </summary>
public static class FilterModes
{
    public const string All = "All";
    public const string Inbound = "Inbound";
    public const string Outbound = "Outbound";
    public const string Internal = "Internal";
    public const string External = "External";
}

/// <summary>
/// Chart type constants for visualization selection.
/// </summary>
public static class ChartTypes
{
    public const string Line = "Line";
    public const string Bar = "Bar";
    public const string Pie = "Pie";
    public const string Area = "Area";
    public const string Donut = "Donut";
    public const string Stacked = "Stacked";
}

/// <summary>
/// Time range constants for filtering.
/// </summary>
public static class TimeRanges
{
    public const string All = "All";
    public const string Last1Min = "1m";
    public const string Last5Min = "5m";
    public const string Last15Min = "15m";
    public const string Last1Hour = "1h";
    public const string Custom = "Custom";
}

/// <summary>
/// Sort direction constants.
/// </summary>
public static class SortDirections
{
    public const string Ascending = "Ascending";
    public const string Descending = "Descending";
}
