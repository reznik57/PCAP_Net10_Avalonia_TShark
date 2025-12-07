using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DuckDB.NET.Data;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services;

public sealed class DuckDbPacketStore : IPacketStore
{
    private const string ThreatConditionSql = "(protocol = 'ICMP' OR src_port IN (445, 139) OR dst_port IN (445, 139) OR LOWER(info) LIKE '%scan%' OR LOWER(info) LIKE '%attack%' OR LOWER(info) LIKE '%malware%' OR LOWER(info) LIKE '%suspicious%')";

    private DuckDBConnection? _connection;
    private string _databasePath = string.Empty;
    private readonly Lock _sync = new();

    public async Task InitializeAsync(string databasePath, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
            throw new ArgumentException("Database path cannot be null", nameof(databasePath));

        lock (_sync)
        {
            _databasePath = databasePath;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);

        await Task.Run(() =>
        {
            lock (_sync)
            {
                DisposeInternal();

                _connection = new DuckDBConnection($"Data Source={databasePath};");
                _connection.Open();

                using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS packets (
                        frame_number      BIGINT,
                        timestamp         TIMESTAMP,
                        length            INTEGER,
                        src_ip            VARCHAR,
                        dst_ip            VARCHAR,
                        src_port          INTEGER,
                        dst_port          INTEGER,
                        protocol          VARCHAR,
                        l7_protocol       VARCHAR,
                        info              VARCHAR
                    );
                    CREATE TABLE IF NOT EXISTS metadata (
                        key STRING PRIMARY KEY,
                        value STRING
                    );
                    CREATE TABLE IF NOT EXISTS flows (
                        src_ip            VARCHAR,
                        dst_ip            VARCHAR,
                        src_port          INTEGER,
                        dst_port          INTEGER,
                        protocol          VARCHAR,
                        packet_count      BIGINT,
                        byte_count        BIGINT,
                        first_seen        TIMESTAMP,
                        last_seen         TIMESTAMP
                    );";
                cmd.ExecuteNonQuery();

            }
        }, cancellationToken).ConfigureAwait(false);
    }

    private const int InsertChunkSize = 1000;

    public Task InsertPacketsAsync(IEnumerable<PacketInfo> packets, CancellationToken cancellationToken = default)
    {
        if (_connection is null)
            throw new InvalidOperationException("Packet store is not initialized");

        var packetList = packets as IList<PacketInfo> ?? packets.ToList();
        if (packetList.Count == 0)
            return Task.CompletedTask;

        lock (_sync)
        {
            using var transaction = _connection.BeginTransaction();

            for (int offset = 0; offset < packetList.Count; offset += InsertChunkSize)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var count = Math.Min(InsertChunkSize, packetList.Count - offset);
                using var cmd = _connection.CreateCommand();

                var builder = new StringBuilder();
                builder.Append("INSERT INTO packets ");
                builder.Append("(frame_number, timestamp, length, src_ip, dst_ip, src_port, dst_port, protocol, l7_protocol, info) VALUES ");

                for (int i = 0; i < count; i++)
                {
                    if (i > 0)
                        builder.Append(", ");

                    builder.Append("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

                    var packet = packetList[offset + i];
                    cmd.Parameters.Add(new DuckDBParameter { Value = (long)packet.FrameNumber });
                    cmd.Parameters.Add(new DuckDBParameter { Value = packet.Timestamp });
                    cmd.Parameters.Add(new DuckDBParameter { Value = (int)packet.Length });
                    cmd.Parameters.Add(new DuckDBParameter { Value = packet.SourceIP });
                    cmd.Parameters.Add(new DuckDBParameter { Value = packet.DestinationIP });
                    cmd.Parameters.Add(new DuckDBParameter { Value = (int)packet.SourcePort });
                    cmd.Parameters.Add(new DuckDBParameter { Value = (int)packet.DestinationPort });
                    cmd.Parameters.Add(new DuckDBParameter { Value = packet.Protocol.ToString() });
                    cmd.Parameters.Add(new DuckDBParameter { Value = packet.L7Protocol ?? string.Empty });
                    cmd.Parameters.Add(new DuckDBParameter { Value = packet.Info ?? string.Empty });
                }

#pragma warning disable CA2100 // Review SQL queries for security vulnerabilities - Query uses parameterized DuckDB commands with safe parameter binding
                cmd.CommandText = builder.ToString();
                cmd.ExecuteNonQuery();
#pragma warning restore CA2100
            }

            transaction.Commit();
        }

        return Task.CompletedTask;
    }

    public Task<PacketQueryResult> QueryPacketsAsync(PacketQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (_connection is null)
            throw new InvalidOperationException("Packet store is not initialized");

        var pageSize = query.PageSize <= 0 ? 100 : query.PageSize; // No upper limit - let caller decide page size
        var pageNumber = query.PageNumber <= 0 ? 1 : query.PageNumber;
        var includeSummary = query.IncludeSummary;
        var includePackets = query.IncludePackets;
        var sortDescending = query.SortDescending;

        return Task.Run(() =>
        {
            lock (_sync)
            {
                var (whereClause, parameterValues) = BuildWhereClause(query.Filter);

                long totalCount = 0;
                long totalBytes = 0;
                long threatCount = 0;
                DateTime? firstTimestamp = null;
                DateTime? lastTimestamp = null;

                if (includeSummary)
                {
                    totalCount = ExecuteScalarLong($"SELECT COUNT(*) FROM packets {whereClause};", parameterValues);

                    if (totalCount > 0)
                    {
                        totalBytes = ExecuteScalarLong($"SELECT COALESCE(SUM(length), 0) FROM packets {whereClause};", parameterValues);

                        (firstTimestamp, lastTimestamp) = ExecuteMinMaxTimestamp(whereClause, parameterValues);

                        var threatClause = CombineWhereClause(whereClause, ThreatConditionSql);
                        threatCount = ExecuteScalarLong($"SELECT COUNT(*) FROM packets {threatClause};", parameterValues);
                    }
                    else
                    {
                        // No packets match filter; ensure page number resets to 1
                        pageNumber = 1;
                    }
                }

                // Adjust page number if beyond available data
                if (includeSummary && totalCount > 0)
                {
                    var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
                    if (pageNumber > totalPages)
                    {
                        pageNumber = totalPages;
                    }
                }

                IReadOnlyList<PacketInfo> packets = [];
                if (includePackets)
                {
                    packets = ExecutePacketQuery(whereClause, parameterValues, pageNumber, pageSize, sortDescending);
                }

                return new PacketQueryResult
                {
                    Packets = packets,
                    TotalCount = totalCount,
                    TotalBytes = totalBytes,
                    ThreatCount = threatCount,
                    FirstPacketTimestamp = firstTimestamp,
                    LastPacketTimestamp = lastTimestamp
                };
            }
        }, cancellationToken);
    }

    public Task InsertFlowsAsync(IEnumerable<FlowRecord> flows, CancellationToken cancellationToken = default)
    {
        if (_connection is null)
            throw new InvalidOperationException("Packet store is not initialized");

        return Task.Run(() =>
        {
            lock (_sync)
            {
                using var transaction = _connection.BeginTransaction();
                using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO flows
                    (src_ip, dst_ip, src_port, dst_port, protocol, packet_count, byte_count, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                ";

                foreach (var flow in flows)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    cmd.Parameters.Clear();
                    cmd.Parameters.AddRange(new[]
                    {
                        new DuckDBParameter { Value = flow.SourceIP },
                        new DuckDBParameter { Value = flow.DestinationIP },
                        new DuckDBParameter { Value = (int)flow.SourcePort },
                        new DuckDBParameter { Value = (int)flow.DestinationPort },
                        new DuckDBParameter { Value = flow.Protocol },
                        new DuckDBParameter { Value = flow.PacketCount },
                        new DuckDBParameter { Value = flow.ByteCount },
                        new DuckDBParameter { Value = flow.FirstSeen },
                        new DuckDBParameter { Value = flow.LastSeen }
                    });
                    cmd.ExecuteNonQuery();
                }

                transaction.Commit();
            }
        }, cancellationToken);
    }

    public Task ClearAsync(CancellationToken cancellationToken = default)
    {
        if (_connection is null)
            return Task.CompletedTask;

        lock (_sync)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "DELETE FROM packets; DELETE FROM flows;";
            cmd.ExecuteNonQuery();
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// DIAGNOSTIC: Get database frame number statistics to verify data integrity
    /// </summary>
    public (long TotalCount, uint MinFrame, uint MaxFrame) GetFrameNumberDiagnostics()
    {
        if (_connection is null)
            throw new InvalidOperationException("Packet store is not initialized");

        lock (_sync)
        {
            using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*), MIN(frame_number), MAX(frame_number) FROM packets;";
            using var reader = cmd.ExecuteReader();

            if (reader.Read())
            {
                var count = reader.GetInt64(0);
                var min = reader.IsDBNull(1) ? 0 : (uint)reader.GetInt64(1);
                var max = reader.IsDBNull(2) ? 0 : (uint)reader.GetInt64(2);

                Console.WriteLine($"[DuckDB Diagnostics] ✅ Database contains {count:N0} packets. Frame range: {min:N0} - {max:N0}");
                return (count, min, max);
            }
        }

        return (0, 0, 0);
    }

    private long ExecuteScalarLong(string sql, IReadOnlyList<object?> parameterValues)
    {
        using var command = CreateCommand(sql, parameterValues);
        var result = command.ExecuteScalar();
        if (result is null || result is DBNull)
            return 0;
        return Convert.ToInt64(result);
    }

    private (DateTime?, DateTime?) ExecuteMinMaxTimestamp(string whereClause, IReadOnlyList<object?> parameterValues)
    {
        var sql = $"SELECT MIN(timestamp), MAX(timestamp) FROM packets {whereClause};";
        using var command = CreateCommand(sql, parameterValues);
        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            DateTime? min = reader.IsDBNull(0) ? null : reader.GetDateTime(0);
            DateTime? max = reader.IsDBNull(1) ? null : reader.GetDateTime(1);
            return (min, max);
        }
        return (null, null);
    }

    private IReadOnlyList<PacketInfo> ExecutePacketQuery(
        string whereClause,
        IReadOnlyList<object?> baseParameters,
        int pageNumber,
        int pageSize,
        bool sortDescending)
    {
        var sqlBuilder = new StringBuilder();
        sqlBuilder.Append("SELECT frame_number, timestamp, length, src_ip, dst_ip, src_port, dst_port, protocol, l7_protocol, info FROM packets ");
        sqlBuilder.Append(whereClause);
        sqlBuilder.Append(" ORDER BY frame_number ");
        sqlBuilder.Append(sortDescending ? "DESC" : "ASC");
        sqlBuilder.Append(" LIMIT ? OFFSET ?;");

        var parameters = CloneParameters(baseParameters);
        parameters.Add(pageSize);
        var offset = Math.Max(0, (pageNumber - 1) * pageSize);
        parameters.Add(offset);

        var finalSql = sqlBuilder.ToString();

        // ✅ DIAGNOSTIC: Use Console.WriteLine directly to ensure output
        Console.WriteLine($"[DuckDbPacketStore] SQL: {finalSql}");
        Console.WriteLine($"[DuckDbPacketStore] Parameters: PageSize={pageSize}, Offset={offset}, WhereClause='{whereClause}'");
        if (baseParameters.Count > 0)
        {
            Console.WriteLine($"[DuckDbPacketStore] Filter parameters: {string.Join(", ", baseParameters.Select((p, i) => $"[{i}]={p}"))}");
        }

        using var command = CreateCommand(finalSql, parameters);
        using var reader = command.ExecuteReader();
        var packets = new List<PacketInfo>();

        while (reader.Read())
        {
            var packet = ReadPacket(reader);
            packets.Add(packet);

            // ✅ DIAGNOSTIC: Log first 5 packets from database to verify frame numbers
            if (packets.Count <= 5)
            {
                Console.WriteLine($"[DuckDbPacketStore] Packet {packets.Count}: FrameNumber={packet.FrameNumber}, SrcIP={packet.SourceIP}, DstIP={packet.DestinationIP}");
            }
        }

        if (packets.Count > 0)
        {
            Console.WriteLine($"[DuckDbPacketStore] Retrieved {packets.Count} packets. Frame range: {packets[0].FrameNumber} - {packets[packets.Count - 1].FrameNumber}");

            // ✅ CHECK FOR DUPLICATES IN DATABASE QUERY RESULT
            var frameGroups = packets.GroupBy(p => p.FrameNumber).Where(g => g.Count() > 1).ToList();
            if (frameGroups.Any())
            {
                Console.WriteLine($"[DuckDbPacketStore] ⚠️ DUPLICATES FROM DATABASE: {string.Join(", ", frameGroups.Select(g => $"{g.Key} (x{g.Count()})"))}");
            }
        }

        return packets;
    }

    private DuckDBCommand CreateCommand(string sql, IReadOnlyList<object?> parameterValues)
    {
        if (_connection is null)
            throw new InvalidOperationException("Packet store is not initialized");

        var command = _connection.CreateCommand();
#pragma warning disable CA2100 // Review SQL queries for security vulnerabilities - Query uses parameterized DuckDB commands with safe parameter binding
        command.CommandText = sql;
#pragma warning restore CA2100

        foreach (var value in parameterValues)
        {
            command.Parameters.Add(new DuckDBParameter { Value = value ?? DBNull.Value });
        }

        return command;
    }

    private static List<object?> CloneParameters(IReadOnlyList<object?> source)
    {
        if (source.Count == 0)
            return new List<object?>();

        var clone = new List<object?>(source.Count);
        for (var i = 0; i < source.Count; i++)
        {
            clone.Add(source[i]);
        }
        return clone;
    }

    private static PacketInfo ReadPacket(IDataRecord record)
    {
        var protocolValue = record.IsDBNull(7) ? string.Empty : record.GetString(7);
        var protocol = Enum.TryParse<Protocol>(protocolValue, out var parsed) ? parsed : Protocol.Unknown;

        return new PacketInfo
        {
            FrameNumber = (uint)record.GetInt64(0),
            Timestamp = record.GetDateTime(1),
            Length = (ushort)record.GetInt32(2),
            SourceIP = record.IsDBNull(3) ? string.Empty : record.GetString(3),
            DestinationIP = record.IsDBNull(4) ? string.Empty : record.GetString(4),
            SourcePort = record.IsDBNull(5) ? (ushort)0 : (ushort)Math.Max(0, record.GetInt32(5)),
            DestinationPort = record.IsDBNull(6) ? (ushort)0 : (ushort)Math.Max(0, record.GetInt32(6)),
            Protocol = protocol,
            L7Protocol = record.IsDBNull(8) ? null : record.GetString(8),
            Info = record.IsDBNull(9) ? null : record.GetString(9),
            Payload = ReadOnlyMemory<byte>.Empty
        };
    }

    private static string CombineWhereClause(string whereClause, string extraCondition)
    {
        if (string.IsNullOrWhiteSpace(whereClause))
            return $"WHERE {extraCondition}";
        return $"{whereClause} AND {extraCondition}";
    }

    private static (string Clause, List<object?> Parameters) BuildWhereClause(PacketFilter? filter)
    {
        var parameters = new List<object?>();
        if (filter is null || filter.IsEmpty)
            return (string.Empty, parameters);

        if (filter.CustomPredicate is not null || (filter.CombinedFilters is not null && filter.CombinedFilters.Count > 0))
            throw new NotSupportedException("Complex packet filters are not supported by the persistent packet store.");

        var conditions = new List<string>();

        var sourceIp = BuildIpCondition("src_ip", filter.SourceIpFilter, filter.NegateSourceIp, parameters);
        if (sourceIp is not null) conditions.Add(sourceIp);

        var destinationIp = BuildIpCondition("dst_ip", filter.DestinationIpFilter, filter.NegateDestinationIp, parameters);
        if (destinationIp is not null) conditions.Add(destinationIp);

        var sourcePort = BuildPortCondition("src_port", filter.SourcePortFilter, filter.NegateSourcePort, parameters);
        if (sourcePort is not null) conditions.Add(sourcePort);

        var destinationPort = BuildPortCondition("dst_port", filter.DestinationPortFilter, filter.NegateDestinationPort, parameters);
        if (destinationPort is not null) conditions.Add(destinationPort);

        if (filter.ProtocolFilter.HasValue)
        {
            var comparison = filter.NegateProtocol ? "<>" : "=";
            conditions.Add($"protocol {comparison} ?");
            parameters.Add(filter.ProtocolFilter.Value.ToString());
        }

        if (filter.MinLength.HasValue)
        {
            conditions.Add("length >= ?");
            parameters.Add(filter.MinLength.Value);
        }

        if (filter.MaxLength.HasValue)
        {
            conditions.Add("length <= ?");
            parameters.Add(filter.MaxLength.Value);
        }

        if (filter.StartTime.HasValue)
        {
            conditions.Add("timestamp >= ?");
            parameters.Add(filter.StartTime.Value);
        }

        if (filter.EndTime.HasValue)
        {
            conditions.Add("timestamp <= ?");
            parameters.Add(filter.EndTime.Value);
        }

        if (!string.IsNullOrWhiteSpace(filter.InfoSearchText))
        {
            var condition = filter.NegateInfo ? "NOT (info ILIKE ?)" : "info ILIKE ?";
            parameters.Add($"%{filter.InfoSearchText.Trim()}%");
            conditions.Add(condition);
        }

        if (conditions.Count == 0)
            return (string.Empty, parameters);

        var clause = "WHERE " + string.Join(" AND ", conditions);
        return (clause, parameters);
    }

    private static string? BuildIpCondition(string columnName, string? filterValue, bool negate, List<object?> parameters)
    {
        if (string.IsNullOrWhiteSpace(filterValue))
            return null;

        var trimmed = filterValue.Trim();
        string operation;
        object parameter;

        if (trimmed.Contains('*', StringComparison.Ordinal) || trimmed.Contains('?', StringComparison.Ordinal))
        {
            operation = negate ? "NOT LIKE" : "LIKE";
            parameter = trimmed.Replace("*", "%", StringComparison.Ordinal).Replace("?", "_", StringComparison.Ordinal);
        }
        else if (trimmed.Contains('/', StringComparison.Ordinal))
        {
            operation = negate ? "NOT LIKE" : "LIKE";
            var prefix = trimmed.Split('/')[0].Trim();
            parameter = prefix + "%";
        }
        else
        {
            operation = negate ? "<>" : "=";
            parameter = trimmed;
        }

        parameters.Add(parameter);
        return $"{columnName} {operation} ?";
    }

    private static string? BuildPortCondition(string columnName, string? filterValue, bool negate, List<object?> parameters)
    {
        if (string.IsNullOrWhiteSpace(filterValue))
            return null;

        var tokens = filterValue
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var segments = new List<string>();

        foreach (var token in tokens)
        {
            if (TryParsePortRange(token, out var start, out var end))
            {
                segments.Add($"{columnName} BETWEEN ? AND ?");
                parameters.Add(start);
                parameters.Add(end);
            }
            else if (ushort.TryParse(token, out var port))
            {
                segments.Add($"{columnName} = ?");
                parameters.Add((int)port);
            }
        }

        if (segments.Count == 0)
            return null;

        var combined = segments.Count == 1 ? segments[0] : "(" + string.Join(" OR ", segments) + ")";
        return negate ? $"NOT {combined}" : combined;
    }

    private static bool TryParsePortRange(string token, out int start, out int end)
    {
        start = 0;
        end = 0;
        var parts = token.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
            return false;

        if (!ushort.TryParse(parts[0], out var a) || !ushort.TryParse(parts[1], out var b))
            return false;

        start = Math.Min(a, b);
        end = Math.Max(a, b);
        return true;
    }

    private void DisposeInternal()
    {
        _connection?.Dispose();
        _connection = null;
    }

    public ValueTask DisposeAsync()
    {
        lock (_sync)
        {
            DisposeInternal();
        }
        return ValueTask.CompletedTask;
    }
}
