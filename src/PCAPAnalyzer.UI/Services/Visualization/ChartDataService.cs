using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Services.Visualization
{
    /// <summary>
    /// Service for processing and aggregating chart data with performance optimizations
    /// </summary>
    public interface IChartDataService
    {
        /// <summary>
        /// Aggregates time-series data for efficient visualization
        /// </summary>
        List<TimeSeriesDataPoint> AggregateTimeSeries(List<TimeSeriesDataPoint> data, TimeSpan interval);

        /// <summary>
        /// Creates histogram data from packet information
        /// </summary>
        Dictionary<string, int> CreateHistogram(List<PacketInfo> packets, Func<PacketInfo, double> valueSelector, int bucketCount);

        /// <summary>
        /// Calculates correlation matrix for multi-dimensional analysis
        /// </summary>
        Dictionary<string, Dictionary<string, double>> CalculateCorrelationMatrix(List<PacketInfo> packets);

        /// <summary>
        /// Prepares data for heatmap visualization
        /// </summary>
        HeatmapData CreateHeatmap(List<PacketInfo> packets, string xDimension, string yDimension);

        /// <summary>
        /// Creates Sankey diagram data for traffic flow
        /// </summary>
        SankeyData CreateSankeyFlow(List<ConversationStatistics> conversations, int maxNodes);

        /// <summary>
        /// Prepares network graph data
        /// </summary>
        NetworkGraphData CreateNetworkGraph(List<ConversationStatistics> conversations, int maxNodes);

        /// <summary>
        /// Calculates statistical distributions
        /// </summary>
        StatisticalDistribution CalculateDistribution(List<double> values);

        /// <summary>
        /// Caches chart data for performance
        /// </summary>
        void CacheChartData(string cacheKey, object data);

        /// <summary>
        /// Retrieves cached chart data
        /// </summary>
        T? GetCachedData<T>(string cacheKey) where T : class;
    }

    public class ChartDataService : IChartDataService
    {
        private readonly Dictionary<string, (object Data, DateTime CachedAt)> _cache = [];
        private readonly TimeSpan _cacheExpiration = TimeSpan.FromMinutes(5);

        public List<TimeSeriesDataPoint> AggregateTimeSeries(List<TimeSeriesDataPoint> data, TimeSpan interval)
        {
            if (data is null || !data.Any())
                return new List<TimeSeriesDataPoint>();

            var aggregated = data
                .GroupBy(d => new DateTime((d.Timestamp.Ticks / interval.Ticks) * interval.Ticks))
                .Select(g => new TimeSeriesDataPoint
                {
                    Timestamp = g.Key,
                    Value = g.Sum(d => d.Value),
                    PacketsPerSecond = g.Average(d => d.PacketsPerSecond),
                    AnomaliesPerSecond = g.Sum(d => d.AnomaliesPerSecond),
                    Series = g.First().Series
                })
                .OrderBy(d => d.Timestamp)
                .ToList();

            return aggregated;
        }

        public Dictionary<string, int> CreateHistogram(List<PacketInfo> packets, Func<PacketInfo, double> valueSelector, int bucketCount)
        {
            if (packets is null || !packets.Any() || bucketCount <= 0)
                return new Dictionary<string, int>();

            var values = packets.Select(valueSelector).Where(v => !double.IsNaN(v) && !double.IsInfinity(v)).ToList();
            if (!values.Any())
                return new Dictionary<string, int>();

            var min = values.Min();
            var max = values.Max();
            var bucketSize = (max - min) / bucketCount;

            if (bucketSize == 0)
                return new Dictionary<string, int> { [$"{min:F2}"] = values.Count };

            var histogram = new Dictionary<string, int>();
            for (int i = 0; i < bucketCount; i++)
            {
                var bucketStart = min + (i * bucketSize);
                var bucketEnd = bucketStart + bucketSize;
                var bucketLabel = $"{bucketStart:F0}-{bucketEnd:F0}";

                var count = values.Count(v => v >= bucketStart && (i == bucketCount - 1 ? v <= bucketEnd : v < bucketEnd));
                histogram[bucketLabel] = count;
            }

            return histogram;
        }

        public Dictionary<string, Dictionary<string, double>> CalculateCorrelationMatrix(List<PacketInfo> packets)
        {
            if (packets is null || !packets.Any())
                return new Dictionary<string, Dictionary<string, double>>();

            var metrics = new Dictionary<string, List<double>>
            {
                ["PacketSize"] = packets.Select(p => (double)p.Length).ToList(),
                ["Protocol"] = packets.Select(p => (double)p.Protocol).ToList(),
                ["TimeDelta"] = CalculateTimeDelta(packets)
            };

            var matrix = new Dictionary<string, Dictionary<string, double>>();
            foreach (var metric1 in metrics)
            {
                matrix[metric1.Key] = new Dictionary<string, double>();
                foreach (var metric2 in metrics)
                {
                    matrix[metric1.Key][metric2.Key] = CalculatePearsonCorrelation(metric1.Value, metric2.Value);
                }
            }

            return matrix;
        }

        public HeatmapData CreateHeatmap(List<PacketInfo> packets, string xDimension, string yDimension)
        {
            if (packets is null || !packets.Any())
                return new HeatmapData();

            var grouped = packets
                .GroupBy(p => (GetDimensionValue(p, xDimension), GetDimensionValue(p, yDimension)))
                .Select(g => new HeatmapCell
                {
                    XValue = g.Key.Item1,
                    YValue = g.Key.Item2,
                    Intensity = g.Count(),
                    Value = g.Sum(p => p.Length)
                })
                .ToList();

            return new HeatmapData
            {
                Cells = grouped,
                XLabels = grouped.Select(c => c.XValue).Distinct().OrderBy(x => x).ToList(),
                YLabels = grouped.Select(c => c.YValue).Distinct().OrderBy(y => y).ToList(),
                MaxIntensity = grouped.Any() ? grouped.Max(c => c.Intensity) : 0
            };
        }

        public SankeyData CreateSankeyFlow(List<ConversationStatistics> conversations, int maxNodes)
        {
            if (conversations is null || !conversations.Any())
                return new SankeyData();

            var topConversations = conversations
                .OrderByDescending(c => c.ByteCount)
                .Take(maxNodes)
                .ToList();

            var nodes = new HashSet<string>();
            var links = new List<SankeyLink>();

            foreach (var conv in topConversations)
            {
                nodes.Add(conv.SourceAddress);
                nodes.Add(conv.DestinationAddress);

                links.Add(new SankeyLink
                {
                    Source = conv.SourceAddress,
                    Target = conv.DestinationAddress,
                    Value = conv.ByteCount,
                    Protocol = conv.Protocol,
                    PacketCount = conv.PacketCount
                });
            }

            return new SankeyData
            {
                Nodes = nodes.Select((n, i) => new SankeyNode { Id = i, Label = n }).ToList(),
                Links = links
            };
        }

        public NetworkGraphData CreateNetworkGraph(List<ConversationStatistics> conversations, int maxNodes)
        {
            if (conversations is null || !conversations.Any())
                return new NetworkGraphData();

            var topConversations = conversations
                .OrderByDescending(c => c.PacketCount)
                .Take(maxNodes)
                .ToList();

            var nodeSet = new Dictionary<string, NetworkNode>();
            var edges = new List<NetworkEdge>();

            foreach (var conv in topConversations)
            {
                if (!nodeSet.ContainsKey(conv.SourceAddress))
                {
                    nodeSet[conv.SourceAddress] = new NetworkNode
                    {
                        Id = conv.SourceAddress,
                        Label = conv.SourceAddress,
                        Size = 0,
                        Type = "source"
                    };
                }

                if (!nodeSet.ContainsKey(conv.DestinationAddress))
                {
                    nodeSet[conv.DestinationAddress] = new NetworkNode
                    {
                        Id = conv.DestinationAddress,
                        Label = conv.DestinationAddress,
                        Size = 0,
                        Type = "destination"
                    };
                }

                nodeSet[conv.SourceAddress].Size += conv.PacketCount;
                nodeSet[conv.DestinationAddress].Size += conv.PacketCount;

                edges.Add(new NetworkEdge
                {
                    Source = conv.SourceAddress,
                    Target = conv.DestinationAddress,
                    Weight = conv.PacketCount,
                    Protocol = conv.Protocol
                });
            }

            return new NetworkGraphData
            {
                Nodes = nodeSet.Values.ToList(),
                Edges = edges
            };
        }

        public StatisticalDistribution CalculateDistribution(List<double> values)
        {
            if (values is null || !values.Any())
                return new StatisticalDistribution();

            var sorted = values.OrderBy(v => v).ToList();
            var count = sorted.Count;

            // Calculate median correctly for both even and odd counts
            double median;
            if (count % 2 == 0)
            {
                // For even count, average the two middle values
                // Example: [1,2,3,4,5,6] -> indices 2 and 3 (0-based) -> values 3 and 4 -> median = 3.5
                median = (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0;
            }
            else
            {
                // For odd count, take the middle value
                // Example: [1,2,3,4,5] -> index 2 (0-based) -> value 3
                median = sorted[count / 2];
            }

            return new StatisticalDistribution
            {
                Count = count,
                Min = sorted.First(),
                Max = sorted.Last(),
                Mean = values.Average(),
                Median = median,
                Q1 = sorted[Math.Max(0, count / 4 - 1)],
                Q3 = sorted[Math.Min(count - 1, count * 3 / 4)],
                StandardDeviation = CalculateStandardDeviation(values),
                Variance = CalculateVariance(values)
            };
        }

        public void CacheChartData(string cacheKey, object data)
        {
            _cache[cacheKey] = (data, DateTime.UtcNow);
            CleanExpiredCache();
        }

        public T? GetCachedData<T>(string cacheKey) where T : class
        {
            if (_cache.TryGetValue(cacheKey, out var cached))
            {
                if (DateTime.UtcNow - cached.CachedAt < _cacheExpiration)
                {
                    return cached.Data as T;
                }
                _cache.Remove(cacheKey);
            }
            return null;
        }

        private void CleanExpiredCache()
        {
            var expired = _cache
                .Where(kvp => DateTime.UtcNow - kvp.Value.CachedAt >= _cacheExpiration)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expired)
            {
                _cache.Remove(key);
            }
        }

        private List<double> CalculateTimeDelta(List<PacketInfo> packets)
        {
            var deltas = new List<double>();
            for (int i = 1; i < packets.Count; i++)
            {
                deltas.Add((packets[i].Timestamp - packets[i - 1].Timestamp).TotalMilliseconds);
            }
            return deltas.Any() ? deltas : new List<double> { 0 };
        }

        private double CalculatePearsonCorrelation(List<double> x, List<double> y)
        {
            if (x.Count != y.Count || x.Count == 0)
                return 0;

            var avgX = x.Average();
            var avgY = y.Average();
            var sum1 = 0.0;
            var sum2 = 0.0;
            var sum3 = 0.0;

            for (int i = 0; i < x.Count; i++)
            {
                var dx = x[i] - avgX;
                var dy = y[i] - avgY;
                sum1 += dx * dy;
                sum2 += dx * dx;
                sum3 += dy * dy;
            }

            var denominator = Math.Sqrt(sum2 * sum3);
            return denominator == 0 ? 0 : sum1 / denominator;
        }

        private double CalculateStandardDeviation(List<double> values)
        {
            return Math.Sqrt(CalculateVariance(values));
        }

        private double CalculateVariance(List<double> values)
        {
            if (!values.Any())
                return 0;

            var mean = values.Average();
            return values.Sum(v => Math.Pow(v - mean, 2)) / values.Count;
        }

        private string GetDimensionValue(PacketInfo packet, string dimension)
        {
            return dimension.ToLower() switch
            {
                "protocol" => packet.Protocol.ToString(),
                "hour" => packet.Timestamp.Hour.ToString(),
                "source" => packet.SourceIP,
                "destination" => packet.DestinationIP,
                _ => "Unknown"
            };
        }
    }

    public class HeatmapData
    {
        public List<HeatmapCell> Cells { get; set; } = [];
        public List<string> XLabels { get; set; } = [];
        public List<string> YLabels { get; set; } = [];
        public long MaxIntensity { get; set; }
    }

    public class HeatmapCell
    {
        public string XValue { get; set; } = string.Empty;
        public string YValue { get; set; } = string.Empty;
        public long Intensity { get; set; }
        public long Value { get; set; }
    }

    public class SankeyData
    {
        public List<SankeyNode> Nodes { get; set; } = [];
        public List<SankeyLink> Links { get; set; } = [];
    }

    public class SankeyNode
    {
        public int Id { get; set; }
        public string Label { get; set; } = string.Empty;
    }

    public class SankeyLink
    {
        public string Source { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public long Value { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public long PacketCount { get; set; }
    }

    public class NetworkGraphData
    {
        public List<NetworkNode> Nodes { get; set; } = [];
        public List<NetworkEdge> Edges { get; set; } = [];
    }

    public class NetworkNode
    {
        public string Id { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public long Size { get; set; }
        public string Type { get; set; } = string.Empty;
    }

    public class NetworkEdge
    {
        public string Source { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public long Weight { get; set; }
        public string Protocol { get; set; } = string.Empty;
    }

    public class StatisticalDistribution
    {
        public int Count { get; set; }
        public double Min { get; set; }
        public double Max { get; set; }
        public double Mean { get; set; }
        public double Median { get; set; }
        public double Q1 { get; set; }
        public double Q3 { get; set; }
        public double StandardDeviation { get; set; }
        public double Variance { get; set; }
        public double IQR => Q3 - Q1;
    }
}
