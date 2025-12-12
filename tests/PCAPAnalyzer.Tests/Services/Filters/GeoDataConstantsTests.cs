using PCAPAnalyzer.UI.Services.Filters;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.Filters;

/// <summary>
/// Tests for GeoDataConstants - geographic data for filter lookups.
/// </summary>
public class GeoDataConstantsTests
{
    #region Continent Countries

    [Fact]
    public void ContinentCountries_ContainsAllContinents()
    {
        var continents = GeoDataConstants.ContinentCountries.Keys.ToList();

        Assert.Contains("EU", continents);
        Assert.Contains("AS", continents);
        Assert.Contains("NA", continents);
        Assert.Contains("SA", continents);
        Assert.Contains("AF", continents);
        Assert.Contains("OC", continents);
    }

    [Theory]
    [InlineData("EU", "DE")]  // Germany in Europe
    [InlineData("EU", "FR")]  // France in Europe
    [InlineData("EU", "GB")]  // UK in Europe
    [InlineData("AS", "CN")]  // China in Asia
    [InlineData("AS", "JP")]  // Japan in Asia
    [InlineData("NA", "US")]  // USA in North America
    [InlineData("NA", "CA")]  // Canada in North America
    [InlineData("SA", "BR")]  // Brazil in South America
    [InlineData("AF", "ZA")]  // South Africa in Africa
    [InlineData("OC", "AU")]  // Australia in Oceania
    public void ContinentCountries_ContainsExpectedCountries(string continent, string country)
    {
        var countries = GeoDataConstants.ContinentCountries[continent];
        Assert.Contains(country, (IEnumerable<string>)countries);
    }

    #endregion

    #region Region Name Mapping

    [Theory]
    [InlineData("Europe", "EU")]
    [InlineData("European Union", "EU")]
    [InlineData("EU", "EU")]
    [InlineData("Asia", "AS")]
    [InlineData("AS", "AS")]
    [InlineData("NorthAmerica", "NA")]
    [InlineData("North America", "NA")]
    [InlineData("NA", "NA")]
    [InlineData("SouthAmerica", "SA")]
    [InlineData("South America", "SA")]
    [InlineData("Africa", "AF")]
    [InlineData("Oceania", "OC")]
    [InlineData("Australia", "OC")]
    public void RegionToContinentCode_MapsCorrectly(string regionName, string expectedCode)
    {
        Assert.True(GeoDataConstants.RegionToContinentCode.TryGetValue(regionName, out var code));
        Assert.Equal(expectedCode, code);
    }

    [Fact]
    public void RegionToContinentCode_IsCaseInsensitive()
    {
        Assert.True(GeoDataConstants.RegionToContinentCode.TryGetValue("europe", out _));
        Assert.True(GeoDataConstants.RegionToContinentCode.TryGetValue("EUROPE", out _));
        Assert.True(GeoDataConstants.RegionToContinentCode.TryGetValue("Europe", out _));
    }

    #endregion

    #region GetCountriesForRegion

    [Fact]
    public void GetCountriesForRegion_ReturnsCorrectCountries()
    {
        var europeCountries = GeoDataConstants.GetCountriesForRegion("Europe");

        Assert.NotEmpty(europeCountries);
        Assert.Contains("DE", (IEnumerable<string>)europeCountries);
        Assert.Contains("FR", (IEnumerable<string>)europeCountries);
        Assert.Contains("GB", (IEnumerable<string>)europeCountries);
    }

    [Fact]
    public void GetCountriesForRegion_ReturnsEmptyForUnknownRegion()
    {
        var countries = GeoDataConstants.GetCountriesForRegion("Unknown");
        Assert.Empty(countries);
    }

    [Fact]
    public void GetCountriesForRegion_ReturnsEmptyForNullOrEmpty()
    {
        Assert.Empty(GeoDataConstants.GetCountriesForRegion(null!));
        Assert.Empty(GeoDataConstants.GetCountriesForRegion(""));
        Assert.Empty(GeoDataConstants.GetCountriesForRegion("   "));
    }

    #endregion

    #region GetCountriesForRegions

    [Fact]
    public void GetCountriesForRegions_CombinesMultipleRegions()
    {
        var countries = GeoDataConstants.GetCountriesForRegions(["Europe", "Asia"]);

        Assert.NotEmpty(countries);
        // Europe
        Assert.Contains("DE", countries);
        Assert.Contains("FR", countries);
        // Asia
        Assert.Contains("CN", countries);
        Assert.Contains("JP", countries);
    }

    [Fact]
    public void GetCountriesForRegions_IgnoresInvalidRegions()
    {
        var countries = GeoDataConstants.GetCountriesForRegions(["Europe", "InvalidRegion"]);

        Assert.NotEmpty(countries);
        Assert.Contains("DE", countries);
    }

    #endregion

    #region GetContinentForCountry

    [Theory]
    [InlineData("DE", "EU")]
    [InlineData("FR", "EU")]
    [InlineData("US", "NA")]
    [InlineData("CN", "AS")]
    [InlineData("BR", "SA")]
    [InlineData("ZA", "AF")]
    [InlineData("AU", "OC")]
    public void GetContinentForCountry_ReturnsCorrectContinent(string country, string expectedContinent)
    {
        var continent = GeoDataConstants.GetContinentForCountry(country);
        Assert.Equal(expectedContinent, continent);
    }

    [Fact]
    public void GetContinentForCountry_ReturnsNullForUnknownCountry()
    {
        var continent = GeoDataConstants.GetContinentForCountry("XX");
        Assert.Null(continent);
    }

    #endregion

    #region IsCountryInRegion

    [Theory]
    [InlineData("DE", "Europe", true)]
    [InlineData("FR", "Europe", true)]
    [InlineData("US", "Europe", false)]
    [InlineData("US", "North America", true)]
    [InlineData("CN", "Asia", true)]
    public void IsCountryInRegion_ReturnsCorrectResult(string country, string region, bool expected)
    {
        Assert.Equal(expected, GeoDataConstants.IsCountryInRegion(country, region));
    }

    #endregion

    #region Utility Methods

    [Fact]
    public void GetAllContinentCodes_ReturnsAllContinents()
    {
        var codes = GeoDataConstants.GetAllContinentCodes().ToList();

        Assert.Equal(6, codes.Count);
        Assert.Contains("EU", codes);
        Assert.Contains("AS", codes);
        Assert.Contains("NA", codes);
        Assert.Contains("SA", codes);
        Assert.Contains("AF", codes);
        Assert.Contains("OC", codes);
    }

    [Fact]
    public void GetAllRegionNames_ReturnsAllVariants()
    {
        var names = GeoDataConstants.GetAllRegionNames().ToList();

        Assert.NotEmpty(names);
        Assert.Contains("Europe", names);
        Assert.Contains("Asia", names);
        Assert.Contains("North America", names);
        Assert.Contains("NorthAmerica", names); // Also includes variant without space
    }

    #endregion
}
