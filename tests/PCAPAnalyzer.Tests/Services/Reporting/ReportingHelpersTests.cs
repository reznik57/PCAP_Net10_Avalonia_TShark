using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using FluentAssertions;
using PCAPAnalyzer.Core.Services.Reporting;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Tests.Services.Reporting
{
    /// <summary>
    /// Comprehensive unit tests for ReportingHelpers static utility class.
    /// Tests formatting, IP analysis, port classification, severity mapping,
    /// anomaly classification, and report metadata generation.
    /// </summary>
    public class ReportingHelpersTests
    {
        #region FormatBytes Tests

        [Theory]
        [InlineData(0, "0.00 B")]
        [InlineData(512, "512.00 B")]
        [InlineData(1024, "1.00 KB")]
        [InlineData(1536, "1.50 KB")]
        [InlineData(1048576, "1.00 MB")]
        [InlineData(1572864, "1.50 MB")]
        [InlineData(1073741824, "1.00 GB")]
        [InlineData(1610612736, "1.50 GB")]
        [InlineData(1099511627776, "1.00 TB")]
        public void FormatBytes_CorrectlyFormatsValues(long bytes, string expected)
        {
            // Act
            var result = ReportingHelpers.FormatBytes(bytes);

            // Assert
            result.Should().Be(expected);
        }

        [Fact]
        public void FormatBytes_HandlesLargeValues()
        {
            // Arrange
            long petabyte = 1024L * 1024L * 1024L * 1024L * 1024L;

            // Act
            var result = ReportingHelpers.FormatBytes(petabyte);

            // Assert
            result.Should().Contain("TB", "values larger than TB still use TB suffix");
        }

        #endregion

        #region FormatPacketCount Tests

        [Theory]
        [InlineData(0, "0")]
        [InlineData(500, "500")]
        [InlineData(999, "999")]
        [InlineData(1000, "1.00K")]
        [InlineData(1500, "1.50K")]
        [InlineData(1000000, "1.00M")]
        [InlineData(2500000, "2.50M")]
        [InlineData(1000000000, "1.00B")]
        [InlineData(3500000000, "3.50B")]
        public void FormatPacketCount_CorrectlyFormatsValues(long count, string expected)
        {
            // Act
            var result = ReportingHelpers.FormatPacketCount(count);

            // Assert
            result.Should().Be(expected);
        }

        #endregion

        #region FormatDuration Tests

        [Theory]
        [InlineData(30, "30.0s")]
        [InlineData(90, "90.0s")]
        [InlineData(3600, "3600.0s")]
        [InlineData(7200, "7200.0s")]
        [InlineData(86400, "86400.0s")]
        [InlineData(172800, "172800.0s")]
        public void FormatDuration_CorrectlyFormatsValues(int seconds, string expected)
        {
            // Arrange
            var duration = TimeSpan.FromSeconds(seconds);

            // Act
            var result = ReportingHelpers.FormatDuration(duration);

            // Assert
            result.Should().Be(expected);
        }

        [Fact]
        public void FormatDuration_HandlesZero()
        {
            // Arrange
            var duration = TimeSpan.Zero;

            // Act
            var result = ReportingHelpers.FormatDuration(duration);

            // Assert
            result.Should().Be("0.0s");
        }

        #endregion

        #region FormatPercentage Tests

        [Theory]
        [InlineData(0.5, "50.0%")]
        [InlineData(0.156, "15.6%")]
        [InlineData(0.0456, "4.56%")]
        [InlineData(0.00789, "0.789%")]
        [InlineData(0.999, "99.9%")]
        [InlineData(1.0, "100.0%")]
        public void FormatPercentage_AdjustsDecimalPlacesAppropriately(double value, string expected)
        {
            // Act
            var result = ReportingHelpers.FormatPercentage(value);

            // Assert
            result.Should().Be(expected);
        }

        #endregion

        #region IsPrivateIP Tests

        [Theory]
        [InlineData("10.0.0.1", true)]
        [InlineData("10.255.255.255", true)]
        [InlineData("172.16.0.1", true)]
        [InlineData("172.31.255.255", true)]
        [InlineData("192.168.0.1", true)]
        [InlineData("192.168.255.255", true)]
        [InlineData("127.0.0.1", true)] // Loopback
        [InlineData("169.254.1.1", true)] // Link-local
        public void IsPrivateIP_IdentifiesPrivateIPsCorrectly(string ip, bool expected)
        {
            // Act
            var result = ReportingHelpers.IsPrivateIP(ip);

            // Assert
            result.Should().Be(expected);
        }

        [Theory]
        [InlineData("8.8.8.8", false)]
        [InlineData("1.1.1.1", false)]
        [InlineData("208.67.222.222", false)]
        [InlineData("172.15.0.1", false)] // Just outside 172.16-31 range
        [InlineData("172.32.0.1", false)] // Just outside 172.16-31 range
        [InlineData("192.167.0.1", false)]
        [InlineData("193.168.0.1", false)]
        public void IsPrivateIP_IdentifiesPublicIPsCorrectly(string ip, bool expected)
        {
            // Act
            var result = ReportingHelpers.IsPrivateIP(ip);

            // Assert
            result.Should().Be(expected);
        }

        [Theory]
        [InlineData("")]
        [InlineData("invalid")]
        [InlineData("256.1.1.1")]
        [InlineData("1.2.3")]
        public void IsPrivateIP_HandlesInvalidInput(string ip)
        {
            // Act
            var result = ReportingHelpers.IsPrivateIP(ip);

            // Assert
            result.Should().BeFalse("invalid IP addresses should return false");
        }

        [Fact]
        public void IsPrivateIP_HandlesNull()
        {
            // Act
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type
            var result = ReportingHelpers.IsPrivateIP(null);
#pragma warning restore CS8625

            // Assert
            result.Should().BeFalse("null IP address should return false");
        }

        #endregion

        #region GetIPType Tests

        [Theory]
        [InlineData("127.0.0.1", "Loopback")]
        [InlineData("127.255.255.255", "Loopback")]
        [InlineData("169.254.1.1", "Link-Local")]
        [InlineData("169.254.255.255", "Link-Local")]
        [InlineData("224.0.0.1", "Multicast")]
        [InlineData("239.255.255.255", "Multicast")]
        [InlineData("10.0.0.1", "Private")]
        [InlineData("172.16.0.1", "Private")]
        [InlineData("192.168.1.1", "Private")]
        [InlineData("8.8.8.8", "Public")]
        [InlineData("1.1.1.1", "Public")]
        public void GetIPType_ClassifiesCorrectly(string ip, string expectedType)
        {
            // Act
            var result = ReportingHelpers.GetIPType(ip);

            // Assert
            result.Should().Be(expectedType);
        }

        [Theory]
        [InlineData("", "Unknown")]
        [InlineData("invalid", "Invalid")]
        [InlineData("256.1.1.1", "Invalid")]
        public void GetIPType_HandlesInvalidInput(string ip, string expected)
        {
            // Act
            var result = ReportingHelpers.GetIPType(ip);

            // Assert
            result.Should().Be(expected);
        }

        [Fact]
        public void GetIPType_HandlesNull()
        {
            // Act
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type
            var result = ReportingHelpers.GetIPType(null);
#pragma warning restore CS8625

            // Assert
            result.Should().Be("Unknown");
        }

        #endregion

        #region GetServiceName Tests

        [Theory]
        [InlineData(21, "FTP")]
        [InlineData(22, "SSH")]
        [InlineData(23, "Telnet")]
        [InlineData(25, "SMTP")]
        [InlineData(53, "DNS")]
        [InlineData(80, "HTTP")]
        [InlineData(443, "HTTPS")]
        [InlineData(3389, "RDP")]
        [InlineData(1433, "MSSQL")]
        [InlineData(3306, "MySQL")]
        [InlineData(5432, "PostgreSQL")]
        public void GetServiceName_ReturnsCorrectNames(int port, string expected)
        {
            // Act
            var result = ReportingHelpers.GetServiceName(port);

            // Assert
            result.Should().Be(expected);
        }

        [Theory]
        [InlineData(100, "System Port")]
        [InlineData(1000, "System Port")]
        [InlineData(1024, "Registered Port")]
        [InlineData(49151, "Registered Port")]
        [InlineData(49152, "Dynamic Port")]
        [InlineData(50000, "Dynamic Port")]
        [InlineData(65535, "Dynamic Port")]
        public void GetServiceName_ClassifiesUnknownPorts(int port, string expected)
        {
            // Act
            var result = ReportingHelpers.GetServiceName(port);

            // Assert
            result.Should().Be(expected);
        }

        #endregion

        #region IsInsecurePort Tests

        [Theory]
        [InlineData(21, true)]   // FTP
        [InlineData(23, true)]   // Telnet
        [InlineData(25, true)]   // SMTP
        [InlineData(69, true)]   // TFTP
        [InlineData(80, true)]   // HTTP
        [InlineData(110, true)]  // POP3
        [InlineData(139, true)]  // NetBIOS
        [InlineData(143, true)]  // IMAP
        [InlineData(161, true)]  // SNMP
        [InlineData(389, true)]  // LDAP
        [InlineData(445, true)]  // SMB
        [InlineData(512, true)]  // rexec
        [InlineData(513, true)]  // rlogin
        [InlineData(514, true)]  // rsh
        [InlineData(1433, true)] // MSSQL
        [InlineData(1521, true)] // Oracle
        [InlineData(3306, true)] // MySQL
        [InlineData(5432, true)] // PostgreSQL
        [InlineData(5900, true)] // VNC
        [InlineData(6379, true)] // Redis
        [InlineData(8080, true)] // HTTP-Alt
        [InlineData(9200, true)] // Elasticsearch
        [InlineData(11211, true)] // Memcached
        [InlineData(27017, true)] // MongoDB
        [InlineData(50000, true)] // SAP
        public void IsInsecurePort_IdentifiesInsecurePortsCorrectly(int port, bool expected)
        {
            // Act
            var result = ReportingHelpers.IsInsecurePort(port);

            // Assert
            result.Should().Be(expected);
        }

        [Theory]
        [InlineData(22, false)]   // SSH - secure
        [InlineData(443, false)]  // HTTPS - secure
        [InlineData(465, false)]  // SMTPS - secure
        [InlineData(993, false)]  // IMAPS - secure
        [InlineData(995, false)]  // POP3S - secure
        [InlineData(12345, false)] // Random port
        public void IsInsecurePort_RecognizesSecurePorts(int port, bool expected)
        {
            // Act
            var result = ReportingHelpers.IsInsecurePort(port);

            // Assert
            result.Should().Be(expected);
        }

        #endregion

        #region GetInsecurePortDescription Tests

        [Theory]
        [InlineData(21, "FTP")]
        [InlineData(23, "Telnet")]
        [InlineData(445, "SMB")]
        [InlineData(3389, "Unknown security risk")]
        public void GetInsecurePortDescription_ReturnsCorrectDescriptions(int port, string expectedPartial)
        {
            // Act
            var result = ReportingHelpers.GetInsecurePortDescription(port);

            // Assert
            result.Should().Contain(expectedPartial, "description should identify the service or risk");
        }

        [Fact]
        public void GetInsecurePortDescription_UnknownPort_ReturnsDefaultMessage()
        {
            // Act
            var result = ReportingHelpers.GetInsecurePortDescription(99999);

            // Assert
            result.Should().Be("Unknown security risk");
        }

        #endregion

        #region GetSeverityPriority Tests

        [Theory]
        [InlineData("CRITICAL", 1)]
        [InlineData("critical", 1)]
        [InlineData("HIGH", 2)]
        [InlineData("high", 2)]
        [InlineData("MEDIUM", 3)]
        [InlineData("medium", 3)]
        [InlineData("LOW", 4)]
        [InlineData("low", 4)]
        [InlineData("INFO", 5)]
        [InlineData("info", 5)]
        [InlineData("UNKNOWN", 6)]
        public void GetSeverityPriority_MapsPriorityCorrectly(string severity, int expected)
        {
            // Act
            var result = ReportingHelpers.GetSeverityPriority(severity);

            // Assert
            result.Should().Be(expected);
        }

        [Fact]
        public void GetSeverityPriority_HandlesNull()
        {
            // Act
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type
            var result = ReportingHelpers.GetSeverityPriority(null);
#pragma warning restore CS8625

            // Assert
            result.Should().Be(6);
        }

        #endregion

        #region GetSeverityColor Tests

        [Theory]
        [InlineData("CRITICAL", "#dc3545")]
        [InlineData("critical", "#dc3545")]
        [InlineData("HIGH", "#fd7e14")]
        [InlineData("high", "#fd7e14")]
        [InlineData("MEDIUM", "#ffc107")]
        [InlineData("medium", "#ffc107")]
        [InlineData("LOW", "#28a745")]
        [InlineData("low", "#28a745")]
        [InlineData("INFO", "#17a2b8")]
        [InlineData("info", "#17a2b8")]
        [InlineData("UNKNOWN", "#6c757d")]
        public void GetSeverityColor_ReturnsCorrectHexColors(string severity, string expected)
        {
            // Act
            var result = ReportingHelpers.GetSeverityColor(severity);

            // Assert
            result.Should().Be(expected);
        }

        [Fact]
        public void GetSeverityColor_HandlesNull()
        {
            // Act
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type
            var result = ReportingHelpers.GetSeverityColor(null);
#pragma warning restore CS8625

            // Assert
            result.Should().Be("#6c757d");
        }

        #endregion

        #region ClassifyAnomalyType Tests

        [Theory]
        [InlineData("Port scan detected on network", "Port Scanning")]
        [InlineData("Scanning activity from 10.0.0.1", "Port Scanning")]
        [InlineData("DDoS attack in progress", "DDoS Attack")]
        [InlineData("Denial of service detected", "DDoS Attack")]
        [InlineData("Data exfiltration to external IP", "Data Exfiltration")]
        [InlineData("Potential data leak detected", "Data Exfiltration")]
        [InlineData("Brute force attack on SSH", "Brute Force")]
        [InlineData("Multiple authentication failures", "Brute Force")]
        [InlineData("Malware signature detected", "Malware")]
        [InlineData("Trojan activity observed", "Malware")]
        [InlineData("Crypto mining traffic", "Crypto Mining")]
        [InlineData("Bitcoin mining detected", "Crypto Mining")]
        [InlineData("IoT device anomaly", "IoT Anomaly")]
        [InlineData("Smart device behaving oddly", "IoT Anomaly")]
        [InlineData("VoIP call quality issue", "VoIP Anomaly")]
        [InlineData("SIP protocol anomaly", "VoIP Anomaly")]
        [InlineData("Unusual protocol usage", "Protocol Anomaly")]
        [InlineData("Large packet sizes detected", "Traffic Anomaly")]
        [InlineData("Oversized frames observed", "Traffic Anomaly")]
        [InlineData("Some other weird thing", "General Anomaly")]
        public void ClassifyAnomalyType_IdentifiesTypesCorrectly(string description, string expected)
        {
            // Act
            var result = ReportingHelpers.ClassifyAnomalyType(description);

            // Assert
            result.Should().Be(expected);
        }

        [Theory]
        [InlineData("")]
        public void ClassifyAnomalyType_HandlesEmptyInput(string description)
        {
            // Act
            var result = ReportingHelpers.ClassifyAnomalyType(description);

            // Assert
            result.Should().Be("Unknown");
        }

        [Fact]
        public void ClassifyAnomalyType_HandlesNull()
        {
            // Act
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type
            var result = ReportingHelpers.ClassifyAnomalyType(null);
#pragma warning restore CS8625

            // Assert
            result.Should().Be("Unknown");
        }

        #endregion

        #region GenerateReportId Tests

        [Fact]
        public void GenerateReportId_CreatesUniqueIds()
        {
            // Act
            var id1 = ReportingHelpers.GenerateReportId();
            var id2 = ReportingHelpers.GenerateReportId();

            // Assert
            id1.Should().NotBe(id2, "each report ID should be unique");
        }

        [Fact]
        public void GenerateReportId_HasCorrectFormat()
        {
            // Act
            var id = ReportingHelpers.GenerateReportId();

            // Assert
            id.Should().StartWith("RPT-");
            id.Should().MatchRegex(@"RPT-\d{8}-\d{6}-[A-F0-9]{8}",
                "format should be RPT-YYYYMMDD-HHMMSS-GUID");
        }

        [Fact]
        public void GenerateReportId_IncludesTimestamp()
        {
            // Act
            var id = ReportingHelpers.GenerateReportId();

            // Assert
            var parts = id.Split('-');
            parts.Should().HaveCountGreaterThanOrEqualTo(3);
            parts[1].Should().HaveLength(8, "date part should be YYYYMMDD");
            parts[2].Should().HaveLength(6, "time part should be HHMMSS");
        }

        #endregion

        #region GetReportClassification Tests

        [Fact]
        public void GetReportClassification_WithCriticalFindings_ReturnsCritical()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                new SecurityFinding { Severity = SeverityLevel.Critical },
                new SecurityFinding { Severity = SeverityLevel.High }
            };

            // Act
            var result = ReportingHelpers.GetReportClassification(findings);

            // Assert
            result.Should().Be("CRITICAL - IMMEDIATE ACTION REQUIRED");
        }

        [Fact]
        public void GetReportClassification_WithHighFindings_ReturnsHigh()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                new SecurityFinding { Severity = SeverityLevel.High },
                new SecurityFinding { Severity = SeverityLevel.Medium }
            };

            // Act
            var result = ReportingHelpers.GetReportClassification(findings);

            // Assert
            result.Should().Be("HIGH - URGENT ATTENTION NEEDED");
        }

        [Fact]
        public void GetReportClassification_WithMediumFindings_ReturnsModerate()
        {
            // Arrange
            var findings = new List<SecurityFinding>
            {
                new SecurityFinding { Severity = SeverityLevel.Medium },
                new SecurityFinding { Severity = SeverityLevel.Low }
            };

            // Act
            var result = ReportingHelpers.GetReportClassification(findings);

            // Assert
            result.Should().Be("MODERATE - REVIEW RECOMMENDED");
        }

        [Fact]
        public void GetReportClassification_WithNoFindings_ReturnsInformational()
        {
            // Arrange
            var findings = new List<SecurityFinding>();

            // Act
            var result = ReportingHelpers.GetReportClassification(findings);

            // Assert
            result.Should().Be("INFORMATIONAL");
        }

        #endregion

        #region ComplianceStandards Tests

        [Fact]
        public void ComplianceStandards_ContainsExpectedStandards()
        {
            // Assert
            ReportingHelpers.ComplianceStandards.Should().ContainKey("PCI-DSS");
            ReportingHelpers.ComplianceStandards.Should().ContainKey("HIPAA");
            ReportingHelpers.ComplianceStandards.Should().ContainKey("GDPR");
            ReportingHelpers.ComplianceStandards.Should().ContainKey("SOX");
            ReportingHelpers.ComplianceStandards.Should().ContainKey("NIST");
        }

        #endregion

        #region InsecurePortDatabase Tests

        [Fact]
        public void InsecurePortDatabase_Contains25Ports()
        {
            // Assert
            ReportingHelpers.InsecurePortDatabase.Should().HaveCount(25,
                "database should contain exactly 25 insecure ports");
        }

        [Fact]
        public void InsecurePortDatabase_ContainsCriticalPorts()
        {
            // Assert
            ReportingHelpers.InsecurePortDatabase.Should().ContainKey(21); // FTP
            ReportingHelpers.InsecurePortDatabase.Should().ContainKey(23); // Telnet
            ReportingHelpers.InsecurePortDatabase.Should().ContainKey(445); // SMB
        }

        #endregion
    }
}
