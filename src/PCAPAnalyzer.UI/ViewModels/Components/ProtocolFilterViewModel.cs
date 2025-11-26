using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for protocol filtering.
/// Handles L7 protocol toggles, VPN protocol filters, and TLS version filters.
/// </summary>
public partial class ProtocolFilterViewModel : ObservableObject
{
    // L7 Protocol filters
    [ObservableProperty] private bool _httpToggle;
    [ObservableProperty] private bool _httpsToggle;
    [ObservableProperty] private bool _dnsToggle;
    [ObservableProperty] private bool _snmpToggle;
    [ObservableProperty] private bool _sshToggle;
    [ObservableProperty] private bool _ftpToggle;
    [ObservableProperty] private bool _smtpToggle;
    [ObservableProperty] private bool _stunToggle;
    [ObservableProperty] private bool _dhcpServerToggle;

    // VPN Protocol filters
    [ObservableProperty] private bool _wireGuardToggle;
    [ObservableProperty] private bool _openVpnToggle;
    [ObservableProperty] private bool _ikeV2Toggle;
    [ObservableProperty] private bool _ipsecToggle;
    [ObservableProperty] private bool _l2tpToggle;
    [ObservableProperty] private bool _pptpToggle;

    // TLS version filters
    [ObservableProperty] private bool _tlsV10Toggle;
    [ObservableProperty] private bool _tlsV11Toggle;
    [ObservableProperty] private bool _tlsV12Toggle;
    [ObservableProperty] private bool _tlsV13Toggle;

    // Protocol list
    [ObservableProperty] private List<string> _availableProtocols = new List<string>();

    /// <summary>
    /// Event raised when any protocol filter changes
    /// </summary>
    public event EventHandler? FilterChanged;

    public ProtocolFilterViewModel()
    {
        InitializeProtocolList();
    }

    /// <summary>
    /// Gets whether any protocol filter is active
    /// </summary>
    public bool HasActiveFilters =>
        HttpToggle || HttpsToggle || DnsToggle || SnmpToggle || SshToggle ||
        FtpToggle || SmtpToggle || StunToggle || DhcpServerToggle ||
        WireGuardToggle || OpenVpnToggle || IkeV2Toggle || IpsecToggle ||
        L2tpToggle || PptpToggle ||
        TlsV10Toggle || TlsV11Toggle || TlsV12Toggle || TlsV13Toggle;

    /// <summary>
    /// Gets count of active protocol filters
    /// </summary>
    public int ActiveFilterCount
    {
        get
        {
            int count = 0;
            if (HttpToggle) count++;
            if (HttpsToggle) count++;
            if (DnsToggle) count++;
            if (SnmpToggle) count++;
            if (SshToggle) count++;
            if (FtpToggle) count++;
            if (SmtpToggle) count++;
            if (StunToggle) count++;
            if (DhcpServerToggle) count++;
            if (WireGuardToggle) count++;
            if (OpenVpnToggle) count++;
            if (IkeV2Toggle) count++;
            if (IpsecToggle) count++;
            if (L2tpToggle) count++;
            if (PptpToggle) count++;
            if (TlsV10Toggle) count++;
            if (TlsV11Toggle) count++;
            if (TlsV12Toggle) count++;
            if (TlsV13Toggle) count++;
            return count;
        }
    }

    /// <summary>
    /// Initializes the available protocols list
    /// </summary>
    private void InitializeProtocolList()
    {
        AvailableProtocols = new List<string>
        {
            "HTTP", "HTTPS", "DNS", "SNMP", "SSH", "FTP", "SMTP", "STUN", "DHCP",
            "WireGuard", "OpenVPN", "IKEv2", "IPSec", "L2TP", "PPTP",
            "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"
        };
    }

    /// <summary>
    /// Clears all protocol filters
    /// </summary>
    public void ClearAll()
    {
        HttpToggle = false;
        HttpsToggle = false;
        DnsToggle = false;
        SnmpToggle = false;
        SshToggle = false;
        FtpToggle = false;
        SmtpToggle = false;
        StunToggle = false;
        DhcpServerToggle = false;
        WireGuardToggle = false;
        OpenVpnToggle = false;
        IkeV2Toggle = false;
        IpsecToggle = false;
        L2tpToggle = false;
        PptpToggle = false;
        TlsV10Toggle = false;
        TlsV11Toggle = false;
        TlsV12Toggle = false;
        TlsV13Toggle = false;

        DebugLogger.Log("[ProtocolFilterViewModel] Cleared all protocol filters");
        FilterChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Gets a description of active protocol filters
    /// </summary>
    public string GetFilterDescription()
    {
        var active = new List<string>();

        // L7 Protocols
        if (HttpToggle) active.Add("HTTP");
        if (HttpsToggle) active.Add("HTTPS");
        if (DnsToggle) active.Add("DNS");
        if (SnmpToggle) active.Add("SNMP");
        if (SshToggle) active.Add("SSH");
        if (FtpToggle) active.Add("FTP");
        if (SmtpToggle) active.Add("SMTP");
        if (StunToggle) active.Add("STUN");
        if (DhcpServerToggle) active.Add("DHCP");

        // VPN Protocols
        if (WireGuardToggle) active.Add("WireGuard");
        if (OpenVpnToggle) active.Add("OpenVPN");
        if (IkeV2Toggle) active.Add("IKEv2");
        if (IpsecToggle) active.Add("IPSec");
        if (L2tpToggle) active.Add("L2TP");
        if (PptpToggle) active.Add("PPTP");

        // TLS Versions
        if (TlsV10Toggle) active.Add("TLSv1.0");
        if (TlsV11Toggle) active.Add("TLSv1.1");
        if (TlsV12Toggle) active.Add("TLSv1.2");
        if (TlsV13Toggle) active.Add("TLSv1.3");

        return active.Count > 0 ? string.Join(", ", active) : "";
    }

    /// <summary>
    /// Gets list of active protocol names
    /// </summary>
    public List<string> GetActiveProtocolNames()
    {
        var active = new List<string>();

        if (HttpToggle) active.Add("HTTP");
        if (HttpsToggle) active.Add("HTTPS");
        if (DnsToggle) active.Add("DNS");
        if (SnmpToggle) active.Add("SNMP");
        if (SshToggle) active.Add("SSH");
        if (FtpToggle) active.Add("FTP");
        if (SmtpToggle) active.Add("SMTP");
        if (StunToggle) active.Add("STUN");
        if (DhcpServerToggle) active.Add("DHCP");
        if (WireGuardToggle) active.Add("WireGuard");
        if (OpenVpnToggle) active.Add("OpenVPN");
        if (IkeV2Toggle) active.Add("IKEv2");
        if (IpsecToggle) active.Add("IPSec");
        if (L2tpToggle) active.Add("L2TP");
        if (PptpToggle) active.Add("PPTP");
        if (TlsV10Toggle) active.Add("TLSv1.0");
        if (TlsV11Toggle) active.Add("TLSv1.1");
        if (TlsV12Toggle) active.Add("TLSv1.2");
        if (TlsV13Toggle) active.Add("TLSv1.3");

        return active;
    }

    // Property change handlers to raise FilterChanged event
    partial void OnHttpToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnHttpsToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnDnsToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnSnmpToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnSshToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnFtpToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnSmtpToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnStunToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnDhcpServerToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnWireGuardToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnOpenVpnToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnIkeV2ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnIpsecToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnL2tpToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnPptpToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnTlsV10ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnTlsV11ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnTlsV12ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnTlsV13ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
}
