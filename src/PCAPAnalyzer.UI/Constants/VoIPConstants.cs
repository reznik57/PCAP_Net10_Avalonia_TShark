namespace PCAPAnalyzer.UI.Constants;

/// <summary>
/// Common VoIP codecs with their typical bandwidth requirements.
/// Reference: ITU-T G-series codecs
/// </summary>
public static class VoIPCodecs
{
    // ITU-T G-series codecs
    public const string G711 = "G.711";      // 64 kbps, uncompressed, low latency
    public const string G729 = "G.729";      // 8 kbps, compressed, good for WAN
    public const string G722 = "G.722";      // 48-64 kbps, wideband audio
    public const string G723 = "G.723";      // 5.3-6.3 kbps, low bandwidth
    public const string G726 = "G.726";      // 16-40 kbps, ADPCM

    // Open/Modern codecs
    public const string Opus = "Opus";       // 6-510 kbps, adaptive, WebRTC
    public const string ILBC = "iLBC";       // 13.3-15.2 kbps, packet loss resilient
    public const string Speex = "Speex";     // 2-44 kbps, open source

    // Mobile codecs
    public const string AMR = "AMR";         // 4.75-12.2 kbps, GSM/3G
    public const string AMRWB = "AMR-WB";    // 6.6-23.85 kbps, HD Voice
    public const string GSM = "GSM";         // 13 kbps, legacy mobile
    public const string EVS = "EVS";         // 5.9-128 kbps, VoLTE

    public static readonly string[] All = new[]
    {
        G711, G729, G722, G723, G726,
        Opus, ILBC, Speex,
        AMR, AMRWB, GSM, EVS
    };

    public static readonly string[] HighQuality = new[] { G711, G722, Opus, EVS };
    public static readonly string[] LowBandwidth = new[] { G729, G723, ILBC, AMR };
}

/// <summary>
/// Common VoIP signaling and media protocols.
/// Reference: RFC 3550 (RTP)
/// </summary>
public static class VoIPProtocols
{
    // Media transport
    public const string RTP = "RTP";         // Real-time Transport Protocol
    public const string RTCP = "RTCP";       // RTP Control Protocol
    public const string SRTP = "SRTP";       // Secure RTP

    // Signaling protocols
    public const string SIP = "SIP";         // Session Initiation Protocol
    public const string H323 = "H.323";      // ITU-T multimedia
    public const string MGCP = "MGCP";       // Media Gateway Control
    public const string SCCP = "SCCP";       // Cisco Skinny
    public const string IAX = "IAX";         // Inter-Asterisk eXchange

    // WebRTC
    public const string STUN = "STUN";       // Session Traversal Utilities
    public const string TURN = "TURN";       // Traversal Using Relay NAT
    public const string ICE = "ICE";         // Interactive Connectivity

    public static readonly string[] All = new[]
    {
        RTP, RTCP, SRTP,
        SIP, H323, MGCP, SCCP, IAX,
        STUN, TURN, ICE
    };

    public static readonly string[] MediaTransport = new[] { RTP, RTCP, SRTP };
    public static readonly string[] Signaling = new[] { SIP, H323, MGCP, SCCP, IAX };
}

/// <summary>
/// DiffServ Code Points (DSCP) for QoS marking.
/// Reference: RFC 2474, RFC 2597 (AF), RFC 3246 (EF)
/// </summary>
public static class VoIPDSCP
{
    // Expedited Forwarding (voice)
    public const string EF = "EF";           // DSCP 46 - Voice traffic

    // Assured Forwarding (video/interactive)
    public const string AF41 = "AF41";       // DSCP 34 - Video conferencing
    public const string AF42 = "AF42";       // DSCP 36 - Video streaming
    public const string AF43 = "AF43";       // DSCP 38 - Video backup

    public const string AF31 = "AF31";       // DSCP 26 - Streaming media
    public const string AF32 = "AF32";       // DSCP 28
    public const string AF33 = "AF33";       // DSCP 30

    public const string AF21 = "AF21";       // DSCP 18 - Transactional data
    public const string AF22 = "AF22";       // DSCP 20
    public const string AF23 = "AF23";       // DSCP 22

    public const string AF11 = "AF11";       // DSCP 10 - Bulk data
    public const string AF12 = "AF12";       // DSCP 12
    public const string AF13 = "AF13";       // DSCP 14

    // Class Selector (legacy)
    public const string CS5 = "CS5";         // DSCP 40 - Signaling
    public const string CS3 = "CS3";         // DSCP 24 - Signaling
    public const string CS0 = "CS0";         // DSCP 0 - Best effort

    public static readonly string[] Voice = new[] { EF };
    public static readonly string[] Video = new[] { AF41, AF42, AF43 };
    public static readonly string[] Signaling = new[] { CS5, CS3 };
    public static readonly string[] All = new[]
    {
        EF,
        AF41, AF42, AF43, AF31, AF32, AF33, AF21, AF22, AF23, AF11, AF12, AF13,
        CS5, CS3, CS0
    };
}

/// <summary>
/// Quality severity levels based on latency/jitter thresholds.
/// </summary>
public static class VoIPQualityLevels
{
    public const string Critical = "Critical";
    public const string High = "High";
    public const string Medium = "Medium";
    public const string Good = "Good";

    public static readonly string[] All = new[] { Critical, High, Medium, Good };
    public static readonly string[] ProblemLevels = new[] { Critical, High };
}

/// <summary>
/// Common VoIP quality thresholds (milliseconds).
/// Reference: ITU-T G.114 recommendations.
/// </summary>
public static class VoIPThresholds
{
    // Latency thresholds
    public const double LatencyCritical = 200.0;  // >200ms unacceptable
    public const double LatencyHigh = 100.0;      // >100ms noticeable delay
    public const double LatencyMedium = 50.0;     // >50ms acceptable

    // Jitter thresholds
    public const double JitterCritical = 50.0;    // >50ms severe quality impact
    public const double JitterHigh = 30.0;        // >30ms noticeable
    public const double JitterMedium = 10.0;      // >10ms acceptable

    // Packet loss thresholds (percentage)
    public const double PacketLossCritical = 5.0;
    public const double PacketLossHigh = 1.0;
    public const double PacketLossMedium = 0.5;
}

/// <summary>
/// Common VoIP port ranges.
/// </summary>
public static class VoIPPorts
{
    public const int SIPDefault = 5060;
    public const int SIPSecure = 5061;
    public const int RTPMin = 16384;
    public const int RTPMax = 32767;
    public const int H323 = 1720;
    public const int MGCPGateway = 2427;
    public const int MGCPCallAgent = 2727;
    public const int SCCPDefault = 2000;
}
