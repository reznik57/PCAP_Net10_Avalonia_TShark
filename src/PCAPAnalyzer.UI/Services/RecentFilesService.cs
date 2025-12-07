using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Service for managing recently opened PCAP files.
/// Persists recent file history to user settings and provides quick access.
/// </summary>
public sealed class RecentFilesService
{
    private const int MaxRecentFiles = 10;
    private const string SettingsFileName = "recent_files.json";
    private readonly string _settingsPath;

    public ObservableCollection<RecentFileInfo> RecentFilesList { get; }

    public event EventHandler<RecentFileInfo>? RecentFileSelected;

    public RecentFilesService()
    {
        // Store settings in user's AppData folder
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appFolder = Path.Combine(appDataPath, "PCAPAnalyzer");
        Directory.CreateDirectory(appFolder);
        _settingsPath = Path.Combine(appFolder, SettingsFileName);

        RecentFilesList = new ObservableCollection<RecentFileInfo>();
        _ = LoadRecentFilesAsync();
    }

    /// <summary>
    /// Add a file to the recent files list
    /// </summary>
    public async Task AddRecentFileAsync(string filePath, long fileSize, int packetCount, TimeSpan analysisDuration)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                DebugLogger.Log($"[RecentFilesService] Invalid file path: {filePath}");
                return;
            }

            // Remove existing entry if present
            var existing = RecentFilesList.FirstOrDefault(f =>
                string.Equals(f.FilePath, filePath, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
            {
                RecentFilesList.Remove(existing);
            }

            // Create new entry
            var fileInfo = new RecentFileInfo(
                FilePath: filePath,
                FileName: Path.GetFileName(filePath),
                AccessedDate: DateTime.Now,
                FileSize: fileSize,
                PacketCount: packetCount,
                AnalysisDuration: analysisDuration,
                IsPinned: false
            );

            // Add to beginning of list
            RecentFilesList.Insert(0, fileInfo);

            // Enforce max size (keep pinned files)
            while (RecentFilesList.Count(f => !f.IsPinned) > MaxRecentFiles)
            {
                var toRemove = RecentFilesList.LastOrDefault(f => !f.IsPinned);
                if (toRemove is not null)
                {
                    RecentFilesList.Remove(toRemove);
                }
            }

            await SaveRecentFilesAsync();
            DebugLogger.Log($"[RecentFilesService] Added recent file: {Path.GetFileName(filePath)}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[RecentFilesService] Error adding recent file: {ex.Message}");
        }
    }

    /// <summary>
    /// Pin a file to keep it at the top of the recent files list
    /// </summary>
    public async Task TogglePinAsync(RecentFileInfo file)
    {
        try
        {
            var fileInList = RecentFilesList.FirstOrDefault(f => f.FilePath == file.FilePath);
            if (fileInList is not null)
            {
                var index = RecentFilesList.IndexOf(fileInList);
                var updated = fileInList with { IsPinned = !fileInList.IsPinned };

                RecentFilesList[index] = updated;

                // Re-sort: pinned files first, then by date
                var sorted = RecentFilesList
                    .OrderByDescending(f => f.IsPinned)
                    .ThenByDescending(f => f.AccessedDate)
                    .ToList();

                RecentFilesList.Clear();
                foreach (var item in sorted)
                {
                    RecentFilesList.Add(item);
                }

                await SaveRecentFilesAsync();
                DebugLogger.Log($"[RecentFilesService] Toggled pin for: {file.FileName}");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[RecentFilesService] Error toggling pin: {ex.Message}");
        }
    }

    /// <summary>
    /// Remove a file from the recent files list
    /// </summary>
    public async Task RemoveRecentFileAsync(RecentFileInfo file)
    {
        try
        {
            RecentFilesList.Remove(file);
            await SaveRecentFilesAsync();
            DebugLogger.Log($"[RecentFilesService] Removed recent file: {file.FileName}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[RecentFilesService] Error removing recent file: {ex.Message}");
        }
    }

    /// <summary>
    /// Clear all recent files
    /// </summary>
    public async Task ClearRecentFilesAsync()
    {
        try
        {
            RecentFilesList.Clear();
            await SaveRecentFilesAsync();
            DebugLogger.Log("[RecentFilesService] Cleared all recent files");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[RecentFilesService] Error clearing recent files: {ex.Message}");
        }
    }

    /// <summary>
    /// Select a recent file (triggers FileSelected event)
    /// </summary>
    public void SelectRecentFile(RecentFileInfo file)
    {
        try
        {
            if (File.Exists(file.FilePath))
            {
                RecentFileSelected?.Invoke(this, file);
                DebugLogger.Log($"[RecentFilesService] Selected recent file: {file.FileName}");
            }
            else
            {
                DebugLogger.Log($"[RecentFilesService] File no longer exists: {file.FilePath}");
                _ = RemoveRecentFileAsync(file);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[RecentFilesService] Error selecting recent file: {ex.Message}");
        }
    }

    /// <summary>
    /// Get recent files as a read-only list
    /// </summary>
    public IReadOnlyList<RecentFileInfo> GetRecentFiles()
    {
        return RecentFilesList.ToList();
    }

    /// <summary>
    /// Load recent files from persistent storage
    /// </summary>
    private async Task LoadRecentFilesAsync()
    {
        try
        {
            if (!File.Exists(_settingsPath))
            {
                DebugLogger.Log("[RecentFilesService] No recent files found");
                return;
            }

            var json = await File.ReadAllTextAsync(_settingsPath);
            var files = JsonSerializer.Deserialize<List<RecentFileInfo>>(json);

            if (files is not null)
            {
                // Verify files still exist
                var validFiles = files.Where(f => File.Exists(f.FilePath)).ToList();

                // Sort: pinned first, then by date
                validFiles = validFiles
                    .OrderByDescending(f => f.IsPinned)
                    .ThenByDescending(f => f.AccessedDate)
                    .ToList();

                RecentFilesList.Clear();
                foreach (var file in validFiles)
                {
                    RecentFilesList.Add(file);
                }

                DebugLogger.Log($"[RecentFilesService] Loaded {RecentFilesList.Count} recent files");
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[RecentFilesService] Error loading recent files: {ex.Message}");
        }
    }

    /// <summary>
    /// Save recent files to persistent storage
    /// </summary>
    private async Task SaveRecentFilesAsync()
    {
        try
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            var json = JsonSerializer.Serialize(RecentFilesList.ToList(), options);
            await File.WriteAllTextAsync(_settingsPath, json);
            DebugLogger.Log($"[RecentFilesService] Saved {RecentFilesList.Count} recent files");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[RecentFilesService] Error saving recent files: {ex.Message}");
        }
    }
}

/// <summary>
/// Information about a recently opened PCAP file
/// </summary>
public record RecentFileInfo(
    string FilePath,
    string FileName,
    DateTime AccessedDate,
    long FileSize,
    int PacketCount,
    TimeSpan AnalysisDuration,
    bool IsPinned = false)
{
    /// <summary>
    /// Human-readable file size (e.g., "2.5 MB")
    /// </summary>
    public string FileSizeFormatted => FileSize.ToFormattedBytes();

    /// <summary>
    /// Human-readable packet count (e.g., "1,234 packets")
    /// </summary>
    public string PacketCountFormatted => $"{PacketCount:N0} packets";

    /// <summary>
    /// Human-readable analysis duration (e.g., "12.5 seconds")
    /// </summary>
    public string AnalysisDurationFormatted => AnalysisDuration.TotalSeconds < 1
        ? $"{AnalysisDuration.TotalMilliseconds:F0} ms"
        : $"{AnalysisDuration.TotalSeconds:F1} sec";

    /// <summary>
    /// Relative time since last access (e.g., "2 hours ago")
    /// </summary>
    public string RelativeAccessTime
    {
        get
        {
            var elapsed = DateTime.Now - AccessedDate;

            if (elapsed.TotalMinutes < 1)
                return "Just now";
            if (elapsed.TotalMinutes < 60)
                return $"{(int)elapsed.TotalMinutes} minutes ago";
            if (elapsed.TotalHours < 24)
                return $"{(int)elapsed.TotalHours} hours ago";
            if (elapsed.TotalDays < 7)
                return $"{(int)elapsed.TotalDays} days ago";
            if (elapsed.TotalDays < 30)
                return $"{(int)(elapsed.TotalDays / 7)} weeks ago";

            return AccessedDate.ToString("MMM dd, yyyy");
        }
    }

    /// <summary>
    /// Pin icon for display (📌 if pinned, empty if not)
    /// </summary>
    public string PinIcon => IsPinned ? "📌" : "";

    /// <summary>
    /// Tooltip text with full details
    /// </summary>
    public string Tooltip => $"""
        File: {FilePath}
        Size: {FileSizeFormatted}
        Packets: {PacketCountFormatted}
        Analysis Time: {AnalysisDurationFormatted}
        Last Accessed: {AccessedDate:yyyy-MM-dd HH:mm:ss}
        {(IsPinned ? "📌 Pinned" : "")}
        """;

}
