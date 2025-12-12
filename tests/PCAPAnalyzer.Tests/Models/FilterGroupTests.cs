using PCAPAnalyzer.UI.Models;
using Xunit;
using FluentAssertions;

namespace PCAPAnalyzer.Tests.Models;

public class FilterGroupTests
{
    #region HasCriteria Tests

    [Fact]
    public void HasCriteria_EmptyGroup_ReturnsFalse()
    {
        var group = new FilterGroup();
        group.HasCriteria().Should().BeFalse();
    }

    [Fact]
    public void HasCriteria_WithSourceIP_ReturnsTrue()
    {
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithDestinationIP_ReturnsTrue()
    {
        var group = new FilterGroup { DestinationIP = "10.0.0.1" };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithPortRange_ReturnsTrue()
    {
        var group = new FilterGroup { PortRange = "80,443" };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithProtocol_ReturnsTrue()
    {
        var group = new FilterGroup { Protocol = "TCP" };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithQuickFilters_ReturnsTrue()
    {
        var group = new FilterGroup { QuickFilters = new List<string> { "Insecure" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithSeverities_ReturnsTrue()
    {
        var group = new FilterGroup { Severities = new List<string> { "Critical", "High" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithThreatCategories_ReturnsTrue()
    {
        var group = new FilterGroup { ThreatCategories = new List<string> { "Malware" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithCodecs_ReturnsTrue()
    {
        var group = new FilterGroup { Codecs = new List<string> { "G.711" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithQualityLevels_ReturnsTrue()
    {
        var group = new FilterGroup { QualityLevels = new List<string> { "Good" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithVoipIssues_ReturnsTrue()
    {
        var group = new FilterGroup { VoipIssues = new List<string> { "High Jitter" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithJitterThreshold_ReturnsTrue()
    {
        var group = new FilterGroup { JitterThreshold = "50" };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithLatencyThreshold_ReturnsTrue()
    {
        var group = new FilterGroup { LatencyThreshold = "100" };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithCountries_ReturnsTrue()
    {
        var group = new FilterGroup { Countries = new List<string> { "US", "CN" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithDirections_ReturnsTrue()
    {
        var group = new FilterGroup { Directions = new List<string> { "Inbound" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithRegions_ReturnsTrue()
    {
        var group = new FilterGroup { Regions = new List<string> { "Europe" } };
        group.HasCriteria().Should().BeTrue();
    }

    [Fact]
    public void HasCriteria_WithEmptyLists_ReturnsFalse()
    {
        var group = new FilterGroup
        {
            QuickFilters = new List<string>(),
            Severities = new List<string>(),
            Countries = new List<string>()
        };
        group.HasCriteria().Should().BeFalse();
    }

    [Fact]
    public void HasCriteria_WithWhitespaceStrings_ReturnsFalse()
    {
        var group = new FilterGroup
        {
            SourceIP = "   ",
            DestinationIP = "",
            PortRange = "\t"
        };
        group.HasCriteria().Should().BeFalse();
    }

    #endregion

    #region GetFieldDescriptions Tests

    [Fact]
    public void GetFieldDescriptions_EmptyGroup_ReturnsEmptyList()
    {
        var group = new FilterGroup();
        group.GetFieldDescriptions().Should().BeEmpty();
    }

    [Fact]
    public void GetFieldDescriptions_WithSourceIP_ReturnsCorrectDescription()
    {
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Src IP: 192.168.1.1");
    }

    [Fact]
    public void GetFieldDescriptions_WithDestinationIP_ReturnsCorrectDescription()
    {
        var group = new FilterGroup { DestinationIP = "10.0.0.1" };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Dest IP: 10.0.0.1");
    }

    [Fact]
    public void GetFieldDescriptions_WithPortRange_ReturnsCorrectDescription()
    {
        var group = new FilterGroup { PortRange = "443" };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Port: 443");
    }

    [Fact]
    public void GetFieldDescriptions_WithProtocol_ReturnsCorrectDescription()
    {
        var group = new FilterGroup { Protocol = "TCP,UDP" };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Protocol: TCP,UDP");
    }

    [Fact]
    public void GetFieldDescriptions_WithMultipleSeverities_ReturnsGrouped()
    {
        // Domain-based grouping: multiple severities grouped into single description with OR
        var group = new FilterGroup { Severities = new List<string> { "Critical", "High" } };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Severity: Critical OR High");
    }

    [Fact]
    public void GetFieldDescriptions_WithCountries_ReturnsGrouped()
    {
        // Domain-based grouping: countries grouped into IP domain with / separator
        var group = new FilterGroup { Countries = new List<string> { "US", "DE" } };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Country: US/DE");
    }

    [Fact]
    public void GetFieldDescriptions_WithJitterThreshold_ReturnsCorrectFormat()
    {
        var group = new FilterGroup { JitterThreshold = "50" };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Jitter: >50ms");
    }

    [Fact]
    public void GetFieldDescriptions_WithLatencyThreshold_ReturnsCorrectFormat()
    {
        var group = new FilterGroup { LatencyThreshold = "100" };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().ContainSingle()
            .Which.Should().Be("Latency: >100ms");
    }

    [Fact]
    public void GetFieldDescriptions_WithMultipleCriteria_ReturnsDomainGrouped()
    {
        // Domain-based grouping: SourceIP and DestIP are in same domain (IP Address)
        // so they're grouped together with OR. Port and Protocol are separate domains.
        var group = new FilterGroup
        {
            SourceIP = "192.168.1.1",
            DestinationIP = "10.0.0.1",
            PortRange = "443",
            Protocol = "TCP"
        };
        var descriptions = group.GetFieldDescriptions();

        descriptions.Should().HaveCount(3);
        descriptions[0].Should().Be("(Src IP: 192.168.1.1 OR Dest IP: 10.0.0.1)");
        descriptions[1].Should().Be("Port: 443");
        descriptions[2].Should().Be("Protocol: TCP");
    }

    #endregion

    #region BuildDisplayLabel Tests

    [Fact]
    public void BuildDisplayLabel_EmptyGroup_SetsEmptyFilterLabel()
    {
        var group = new FilterGroup();
        group.BuildDisplayLabel();

        group.DisplayLabel.Should().Be("(empty filter)");
    }

    [Fact]
    public void BuildDisplayLabel_SingleCriteria_SetsSimpleLabel()
    {
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        group.BuildDisplayLabel();

        group.DisplayLabel.Should().Be("Src IP: 192.168.1.1");
    }

    [Fact]
    public void BuildDisplayLabel_AndGroup_JoinsWithAND()
    {
        var group = new FilterGroup
        {
            SourceIP = "192.168.1.1",
            PortRange = "443",
            IsAndGroup = true
        };
        group.BuildDisplayLabel();

        group.DisplayLabel.Should().Be("Src IP: 192.168.1.1 AND Port: 443");
    }

    [Fact]
    public void BuildDisplayLabel_DifferentDomains_AlwaysJoinsWithAND()
    {
        // Domain-based grouping: different domains (IP vs Port) always AND'd together
        // regardless of IsAndGroup flag (OR logic only applies within domains)
        var group = new FilterGroup
        {
            SourceIP = "192.168.1.1",
            PortRange = "443",
            IsAndGroup = false
        };
        group.BuildDisplayLabel();

        group.DisplayLabel.Should().Be("Src IP: 192.168.1.1 AND Port: 443");
    }

    [Fact]
    public void BuildDisplayLabel_ComplexGroup_JoinsAllCriteria()
    {
        var group = new FilterGroup
        {
            SourceIP = "192.168.0.0/16",
            PortRange = "2598",
            Protocol = "TCP",
            Countries = new List<string> { "US" },
            IsAndGroup = true
        };
        group.BuildDisplayLabel();

        group.DisplayLabel.Should().Contain("Src IP: 192.168.0.0/16");
        group.DisplayLabel.Should().Contain("Port: 2598");
        group.DisplayLabel.Should().Contain("Protocol: TCP");
        group.DisplayLabel.Should().Contain("Country: US");
        group.DisplayLabel.Should().Contain(" AND ");
    }

    #endregion

    #region Constructor Tests

    [Fact]
    public void Constructor_Default_InitializesWithDefaults()
    {
        var group = new FilterGroup();

        group.GroupId.Should().Be(0);
        group.DisplayLabel.Should().BeEmpty();
        group.IsAndGroup.Should().BeFalse();
        group.IsExcludeGroup.Should().BeFalse();
    }

    [Fact]
    public void Constructor_WithParameters_SetsAllProperties()
    {
        var group = new FilterGroup(42, "Test Label", true, true);

        group.GroupId.Should().Be(42);
        group.DisplayLabel.Should().Be("Test Label");
        group.IsAndGroup.Should().BeTrue();
        group.IsExcludeGroup.Should().BeTrue();
    }

    #endregion

    #region GetThreatCriteria Tests

    [Fact]
    public void GetThreatCriteria_NoCriteria_ReturnsNull()
    {
        var group = new FilterGroup();
        group.GetThreatCriteria().Should().BeNull();
    }

    [Fact]
    public void GetThreatCriteria_WithSeverities_ReturnsCriteria()
    {
        var group = new FilterGroup { Severities = new List<string> { "Critical", "High" } };
        var criteria = group.GetThreatCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Severities.Should().HaveCount(2);
        criteria.Value.Severities.Should().Contain("Critical");
        criteria.Value.Severities.Should().Contain("High");
    }

    [Fact]
    public void GetThreatCriteria_WithCategories_ReturnsCriteria()
    {
        var group = new FilterGroup { ThreatCategories = new List<string> { "Malware", "Vulnerability" } };
        var criteria = group.GetThreatCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Categories.Should().HaveCount(2);
        criteria.Value.Categories.Should().Contain("Malware");
    }

    [Fact]
    public void GetThreatCriteria_WithBothSeveritiesAndCategories_ReturnsBoth()
    {
        var group = new FilterGroup
        {
            Severities = new List<string> { "Critical" },
            ThreatCategories = new List<string> { "Malware" }
        };
        var criteria = group.GetThreatCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Severities.Should().ContainSingle().Which.Should().Be("Critical");
        criteria.Value.Categories.Should().ContainSingle().Which.Should().Be("Malware");
    }

    [Fact]
    public void GetThreatCriteria_EmptyLists_ReturnsNull()
    {
        var group = new FilterGroup
        {
            Severities = new List<string>(),
            ThreatCategories = new List<string>()
        };
        group.GetThreatCriteria().Should().BeNull();
    }

    #endregion

    #region GetVoiceQoSCriteria Tests

    [Fact]
    public void GetVoiceQoSCriteria_NoCriteria_ReturnsNull()
    {
        var group = new FilterGroup();
        group.GetVoiceQoSCriteria().Should().BeNull();
    }

    [Fact]
    public void GetVoiceQoSCriteria_WithCodecs_ReturnsCriteria()
    {
        var group = new FilterGroup { Codecs = new List<string> { "G.711", "G.729" } };
        var criteria = group.GetVoiceQoSCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Codecs.Should().HaveCount(2);
        criteria.Value.Codecs.Should().Contain("G.711");
        criteria.Value.Codecs.Should().Contain("G.729");
    }

    [Fact]
    public void GetVoiceQoSCriteria_WithQualityLevels_ReturnsCriteria()
    {
        var group = new FilterGroup { QualityLevels = new List<string> { "Critical", "High" } };
        var criteria = group.GetVoiceQoSCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Qualities.Should().Contain("Critical");
    }

    [Fact]
    public void GetVoiceQoSCriteria_WithVoipIssues_ReturnsCriteria()
    {
        var group = new FilterGroup { VoipIssues = new List<string> { "High Jitter", "Packet Loss" } };
        var criteria = group.GetVoiceQoSCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Issues.Should().HaveCount(2);
    }

    [Fact]
    public void GetVoiceQoSCriteria_WithAllCriteria_ReturnsAll()
    {
        var group = new FilterGroup
        {
            Codecs = new List<string> { "Opus" },
            QualityLevels = new List<string> { "High" },
            VoipIssues = new List<string> { "Jitter" }
        };
        var criteria = group.GetVoiceQoSCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Codecs.Should().ContainSingle();
        criteria.Value.Qualities.Should().ContainSingle();
        criteria.Value.Issues.Should().ContainSingle();
    }

    [Fact]
    public void GetVoiceQoSCriteria_EmptyLists_ReturnsNull()
    {
        var group = new FilterGroup
        {
            Codecs = new List<string>(),
            QualityLevels = new List<string>(),
            VoipIssues = new List<string>()
        };
        group.GetVoiceQoSCriteria().Should().BeNull();
    }

    #endregion

    #region GetCountryCriteria Tests

    [Fact]
    public void GetCountryCriteria_NoCriteria_ReturnsNull()
    {
        var group = new FilterGroup();
        group.GetCountryCriteria().Should().BeNull();
    }

    [Fact]
    public void GetCountryCriteria_WithCountries_ReturnsCriteria()
    {
        var group = new FilterGroup { Countries = new List<string> { "US", "DE", "CN" } };
        var criteria = group.GetCountryCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Countries.Should().HaveCount(3);
        criteria.Value.Countries.Should().Contain("US");
        criteria.Value.Countries.Should().Contain("DE");
    }

    [Fact]
    public void GetCountryCriteria_WithRegions_ReturnsCriteria()
    {
        var group = new FilterGroup { Regions = new List<string> { "Europe", "Asia" } };
        var criteria = group.GetCountryCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Regions.Should().HaveCount(2);
        criteria.Value.Regions.Should().Contain("Europe");
    }

    [Fact]
    public void GetCountryCriteria_WithBothCountriesAndRegions_ReturnsBoth()
    {
        var group = new FilterGroup
        {
            Countries = new List<string> { "US" },
            Regions = new List<string> { "Europe" }
        };
        var criteria = group.GetCountryCriteria();

        criteria.Should().NotBeNull();
        criteria!.Value.Countries.Should().ContainSingle();
        criteria.Value.Regions.Should().ContainSingle();
    }

    [Fact]
    public void GetCountryCriteria_EmptyLists_ReturnsNull()
    {
        var group = new FilterGroup
        {
            Countries = new List<string>(),
            Regions = new List<string>()
        };
        group.GetCountryCriteria().Should().BeNull();
    }

    #endregion
}
