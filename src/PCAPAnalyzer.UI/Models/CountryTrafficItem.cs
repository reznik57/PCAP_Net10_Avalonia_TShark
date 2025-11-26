namespace PCAPAnalyzer.UI.Models
{
    public class CountryTrafficItem
    {
        public int Rank { get; set; }
        public string CountryName { get; set; } = string.Empty;
        public string CountryCode { get; set; } = string.Empty;
        public long PacketCount { get; set; }
        public long ByteCount { get; set; }
        public double TrafficPercentage { get; set; }
        public string Continent { get; set; } = string.Empty;
    }
}