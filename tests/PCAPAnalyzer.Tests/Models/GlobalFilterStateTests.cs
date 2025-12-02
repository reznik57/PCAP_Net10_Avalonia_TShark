using PCAPAnalyzer.UI.Models;
using Xunit;
using FluentAssertions;

namespace PCAPAnalyzer.Tests.Models;

public class GlobalFilterStateTests
{
    #region Basic Filter Tests

    [Fact]
    public void AddIncludeFilter_IncreasesVersion()
    {
        var state = new GlobalFilterState();
        var initialVersion = state.Version;

        state.AddIncludeProtocol("TCP");

        Assert.Equal(initialVersion + 1, state.Version);
    }

    [Fact]
    public void AddExcludeFilter_IncreasesVersion()
    {
        var state = new GlobalFilterState();
        var initialVersion = state.Version;

        state.AddExcludeIP("192.168.1.1");

        Assert.Equal(initialVersion + 1, state.Version);
    }

    [Fact]
    public void Clear_ResetsAllFiltersAndIncreasesVersion()
    {
        var state = new GlobalFilterState();
        state.AddIncludeProtocol("TCP");
        state.AddExcludeIP("10.0.0.1");
        var versionAfterAdds = state.Version;

        state.Clear();

        Assert.Empty(state.IncludeFilters.Protocols);
        Assert.Empty(state.ExcludeFilters.IPs);
        Assert.Equal(versionAfterAdds + 1, state.Version);
    }

    [Fact]
    public void HasActiveFilters_ReturnsTrueWhenFiltersExist()
    {
        var state = new GlobalFilterState();
        Assert.False(state.HasActiveFilters);

        state.AddIncludeProtocol("TCP");

        Assert.True(state.HasActiveFilters);
    }

    #endregion

    #region Filter Group Tests

    [Fact]
    public void AddIncludeGroup_AddsGroupToCollection()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1", PortRange = "443" };

        state.AddIncludeGroup(group);

        state.IncludeGroups.Should().HaveCount(1);
        state.IncludeGroups[0].Should().BeSameAs(group);
    }

    [Fact]
    public void AddIncludeGroup_AssignsUniqueGroupId()
    {
        var state = new GlobalFilterState();
        var group1 = new FilterGroup { SourceIP = "192.168.1.1" };
        var group2 = new FilterGroup { SourceIP = "10.0.0.1" };

        state.AddIncludeGroup(group1);
        state.AddIncludeGroup(group2);

        group1.GroupId.Should().NotBe(group2.GroupId);
        group1.GroupId.Should().BeGreaterThan(0);
        group2.GroupId.Should().BeGreaterThan(0);
    }

    [Fact]
    public void AddIncludeGroup_SetsIsAndGroupTrue()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };

        state.AddIncludeGroup(group);

        group.IsAndGroup.Should().BeTrue();
    }

    [Fact]
    public void AddIncludeGroup_SetsIsExcludeGroupFalse()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };

        state.AddIncludeGroup(group);

        group.IsExcludeGroup.Should().BeFalse();
    }

    [Fact]
    public void AddIncludeGroup_BuildsDisplayLabel()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1", PortRange = "443" };

        state.AddIncludeGroup(group);

        group.DisplayLabel.Should().Contain("Src IP: 192.168.1.1");
        group.DisplayLabel.Should().Contain("Port: 443");
    }

    [Fact]
    public void AddIncludeGroup_IncreasesVersion()
    {
        var state = new GlobalFilterState();
        var initialVersion = state.Version;
        var group = new FilterGroup { SourceIP = "192.168.1.1" };

        state.AddIncludeGroup(group);

        state.Version.Should().Be(initialVersion + 1);
    }

    [Fact]
    public void AddExcludeGroup_AddsGroupToExcludeCollection()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };

        state.AddExcludeGroup(group);

        state.ExcludeGroups.Should().HaveCount(1);
        state.IncludeGroups.Should().BeEmpty();
    }

    [Fact]
    public void AddExcludeGroup_SetsIsExcludeGroupTrue()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };

        state.AddExcludeGroup(group);

        group.IsExcludeGroup.Should().BeTrue();
    }

    [Fact]
    public void RemoveGroup_RemovesIncludeGroup()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        state.AddIncludeGroup(group);
        var groupId = group.GroupId;

        state.RemoveGroup(groupId, isExclude: false);

        state.IncludeGroups.Should().BeEmpty();
    }

    [Fact]
    public void RemoveGroup_RemovesExcludeGroup()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        state.AddExcludeGroup(group);
        var groupId = group.GroupId;

        state.RemoveGroup(groupId, isExclude: true);

        state.ExcludeGroups.Should().BeEmpty();
    }

    [Fact]
    public void RemoveGroup_IncreasesVersion()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        state.AddIncludeGroup(group);
        var versionAfterAdd = state.Version;

        state.RemoveGroup(group.GroupId, isExclude: false);

        state.Version.Should().Be(versionAfterAdd + 1);
    }

    [Fact]
    public void RemoveGroup_DoesNotIncrementVersion_WhenGroupNotFound()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        state.AddIncludeGroup(group);
        var versionAfterAdd = state.Version;

        state.RemoveGroup(999, isExclude: false); // Non-existent ID

        state.Version.Should().Be(versionAfterAdd);
    }

    [Fact]
    public void RemoveGroup_OnlyRemovesSpecificGroup()
    {
        var state = new GlobalFilterState();
        var group1 = new FilterGroup { SourceIP = "192.168.1.1" };
        var group2 = new FilterGroup { SourceIP = "10.0.0.1" };
        var group3 = new FilterGroup { DestinationIP = "8.8.8.8" };
        state.AddIncludeGroup(group1);
        state.AddIncludeGroup(group2);
        state.AddIncludeGroup(group3);

        state.RemoveGroup(group2.GroupId, isExclude: false);

        state.IncludeGroups.Should().HaveCount(2);
        state.IncludeGroups.Should().Contain(group1);
        state.IncludeGroups.Should().Contain(group3);
        state.IncludeGroups.Should().NotContain(group2);
    }

    #endregion

    #region Multiple Groups (OR Logic) Tests

    [Fact]
    public void MultipleGroups_AreStoredSeparately()
    {
        var state = new GlobalFilterState();

        // Group 1: Source IP AND Port
        var group1 = new FilterGroup
        {
            SourceIP = "192.168.0.0/16",
            PortRange = "2598"
        };
        state.AddIncludeGroup(group1);

        // Group 2: Protocol only
        var group2 = new FilterGroup
        {
            Protocol = "TCP"
        };
        state.AddIncludeGroup(group2);

        // Both groups should exist independently (OR'd together)
        state.IncludeGroups.Should().HaveCount(2);
        state.IncludeGroups[0].SourceIP.Should().Be("192.168.0.0/16");
        state.IncludeGroups[0].PortRange.Should().Be("2598");
        state.IncludeGroups[1].Protocol.Should().Be("TCP");
    }

    [Fact]
    public void MultipleGroups_HaveDistinctDisplayLabels()
    {
        var state = new GlobalFilterState();

        var group1 = new FilterGroup { SourceIP = "192.168.1.1", PortRange = "443" };
        var group2 = new FilterGroup { Protocol = "UDP" };

        state.AddIncludeGroup(group1);
        state.AddIncludeGroup(group2);

        state.IncludeGroups[0].DisplayLabel.Should().Contain("Src IP: 192.168.1.1");
        state.IncludeGroups[0].DisplayLabel.Should().Contain("Port: 443");
        state.IncludeGroups[1].DisplayLabel.Should().Be("Protocol: UDP");
    }

    [Fact]
    public void MixedIncludeExcludeGroups_StoredInSeparateCollections()
    {
        var state = new GlobalFilterState();

        var includeGroup = new FilterGroup { SourceIP = "192.168.1.1" };
        var excludeGroup = new FilterGroup { DestinationIP = "10.0.0.1" };

        state.AddIncludeGroup(includeGroup);
        state.AddExcludeGroup(excludeGroup);

        state.IncludeGroups.Should().HaveCount(1);
        state.ExcludeGroups.Should().HaveCount(1);
        state.IncludeGroups[0].IsExcludeGroup.Should().BeFalse();
        state.ExcludeGroups[0].IsExcludeGroup.Should().BeTrue();
    }

    #endregion

    #region Clear Tests

    [Fact]
    public void Clear_RemovesAllGroups()
    {
        var state = new GlobalFilterState();
        state.AddIncludeGroup(new FilterGroup { SourceIP = "192.168.1.1" });
        state.AddIncludeGroup(new FilterGroup { PortRange = "443" });
        state.AddExcludeGroup(new FilterGroup { Protocol = "ICMP" });

        state.Clear();

        state.IncludeGroups.Should().BeEmpty();
        state.ExcludeGroups.Should().BeEmpty();
    }

    [Fact]
    public void Clear_RemovesBothFlatFiltersAndGroups()
    {
        var state = new GlobalFilterState();
        state.AddIncludeProtocol("TCP");
        state.AddExcludeIP("10.0.0.1");
        state.AddIncludeGroup(new FilterGroup { SourceIP = "192.168.1.1" });

        state.Clear();

        state.IncludeFilters.Protocols.Should().BeEmpty();
        state.ExcludeFilters.IPs.Should().BeEmpty();
        state.IncludeGroups.Should().BeEmpty();
    }

    #endregion

    #region HasActiveFilters with Groups Tests

    [Fact]
    public void HasActiveFilters_ReturnsTrueWhenIncludeGroupExists()
    {
        var state = new GlobalFilterState();
        state.HasActiveFilters.Should().BeFalse();

        state.AddIncludeGroup(new FilterGroup { SourceIP = "192.168.1.1" });

        state.HasActiveFilters.Should().BeTrue();
    }

    [Fact]
    public void HasActiveFilters_ReturnsTrueWhenExcludeGroupExists()
    {
        var state = new GlobalFilterState();
        state.HasActiveFilters.Should().BeFalse();

        state.AddExcludeGroup(new FilterGroup { SourceIP = "192.168.1.1" });

        state.HasActiveFilters.Should().BeTrue();
    }

    [Fact]
    public void HasActiveFilters_ReturnsFalseAfterClear()
    {
        var state = new GlobalFilterState();
        state.AddIncludeGroup(new FilterGroup { SourceIP = "192.168.1.1" });
        state.HasActiveFilters.Should().BeTrue();

        state.Clear();

        state.HasActiveFilters.Should().BeFalse();
    }

    #endregion

    #region OnFilterChanged Event Tests

    [Fact]
    public void AddIncludeGroup_FiresOnFilterChangedEvent()
    {
        var state = new GlobalFilterState();
        var eventFired = false;
        state.OnFilterChanged += () => eventFired = true;

        state.AddIncludeGroup(new FilterGroup { SourceIP = "192.168.1.1" });

        eventFired.Should().BeTrue();
    }

    [Fact]
    public void RemoveGroup_FiresOnFilterChangedEvent()
    {
        var state = new GlobalFilterState();
        var group = new FilterGroup { SourceIP = "192.168.1.1" };
        state.AddIncludeGroup(group);

        var eventFired = false;
        state.OnFilterChanged += () => eventFired = true;

        state.RemoveGroup(group.GroupId, isExclude: false);

        eventFired.Should().BeTrue();
    }

    #endregion

    #region Complex Scenario Tests

    [Fact]
    public void ComplexScenario_MultipleGroupsWithAllCriteriaTypes()
    {
        var state = new GlobalFilterState();

        // Group 1: General tab criteria
        var group1 = new FilterGroup
        {
            SourceIP = "192.168.0.0/16",
            PortRange = "2598",
            Protocol = "TCP"
        };
        state.AddIncludeGroup(group1);

        // Group 2: Threats tab criteria
        var group2 = new FilterGroup
        {
            Severities = new List<string> { "Critical", "High" },
            ThreatCategories = new List<string> { "Malware" }
        };
        state.AddIncludeGroup(group2);

        // Group 3: Country tab criteria
        var group3 = new FilterGroup
        {
            Countries = new List<string> { "CN", "RU" },
            Directions = new List<string> { "Inbound" }
        };
        state.AddExcludeGroup(group3);

        // Verify structure
        state.IncludeGroups.Should().HaveCount(2);
        state.ExcludeGroups.Should().HaveCount(1);

        // Verify Group 1
        state.IncludeGroups[0].SourceIP.Should().Be("192.168.0.0/16");
        state.IncludeGroups[0].PortRange.Should().Be("2598");
        state.IncludeGroups[0].Protocol.Should().Be("TCP");
        state.IncludeGroups[0].DisplayLabel.Should().Contain(" AND ");

        // Verify Group 2
        state.IncludeGroups[1].Severities.Should().Contain("Critical");
        state.IncludeGroups[1].Severities.Should().Contain("High");
        state.IncludeGroups[1].ThreatCategories.Should().Contain("Malware");

        // Verify Group 3 (Exclude)
        state.ExcludeGroups[0].Countries.Should().Contain("CN");
        state.ExcludeGroups[0].Countries.Should().Contain("RU");
        state.ExcludeGroups[0].IsExcludeGroup.Should().BeTrue();
    }

    [Fact]
    public void GroupIds_AreSequentialAcrossIncludeAndExclude()
    {
        var state = new GlobalFilterState();

        var include1 = new FilterGroup { SourceIP = "1.1.1.1" };
        var exclude1 = new FilterGroup { SourceIP = "2.2.2.2" };
        var include2 = new FilterGroup { SourceIP = "3.3.3.3" };

        state.AddIncludeGroup(include1);
        state.AddExcludeGroup(exclude1);
        state.AddIncludeGroup(include2);

        // IDs should be sequential regardless of include/exclude
        include1.GroupId.Should().Be(1);
        exclude1.GroupId.Should().Be(2);
        include2.GroupId.Should().Be(3);
    }

    #endregion
}
