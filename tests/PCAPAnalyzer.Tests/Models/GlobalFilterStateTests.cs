using PCAPAnalyzer.UI.Models;
using Xunit;

namespace PCAPAnalyzer.Tests.Models;

public class GlobalFilterStateTests
{
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
}
