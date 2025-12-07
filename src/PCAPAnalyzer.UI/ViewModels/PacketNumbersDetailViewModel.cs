using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

public partial class PacketNumberViewModel : ObservableObject
{
    [ObservableProperty] private int _number;
    [ObservableProperty] private string _packetInfo = string.Empty;
}

public partial class PacketNumbersDetailViewModel : ObservableObject
{
    [ObservableProperty] private string _title = "Packet Details";
    [ObservableProperty] private string _entryType = "";
    [ObservableProperty] private string _entryValue = "";
    [ObservableProperty] private int _totalPackets;
    [ObservableProperty] private long _totalBytes;
    [ObservableProperty] private string _totalBytesFormatted = "0 B";
    [ObservableProperty] private string _displayRange = "All";
    [ObservableProperty] private ObservableCollection<PacketNumberViewModel> _packetNumbers = [];
    private ObservableCollection<PacketNumberViewModel> _allPacketNumbers = [];

    public PacketNumbersDetailViewModel()
    {
        PropertyChanged += OnPropertyChanged;
    }

    private void OnPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DisplayRange))
        {
            UpdateDisplayedPackets();
        }
        else if (e.PropertyName == nameof(TotalBytes))
        {
            TotalBytesFormatted = NumberFormatter.FormatBytes(TotalBytes);
        }
    }

    public void Initialize(string entryType, string entryValue, int[] packetNumbers, long totalBytes = 0)
    {
        EntryType = entryType;
        EntryValue = entryValue;
        TotalPackets = packetNumbers.Length;
        TotalBytes = totalBytes;
        
        Title = $"Packet Details - {entryType}: {entryValue}";
        
        _allPacketNumbers.Clear();
        foreach (var num in packetNumbers.OrderBy(n => n))
        {
            _allPacketNumbers.Add(new PacketNumberViewModel
            {
                Number = num,
                PacketInfo = $"Packet #{num} - {entryType}: {entryValue}"
            });
        }
        
        UpdateDisplayedPackets();
    }

    private void UpdateDisplayedPackets()
    {
        PacketNumbers.Clear();
        
        var itemsToShow = DisplayRange switch
        {
            "First 100" => _allPacketNumbers.Take(100),
            "First 500" => _allPacketNumbers.Take(500),
            "First 1000" => _allPacketNumbers.Take(1000),
            _ => _allPacketNumbers
        };

        foreach (var item in itemsToShow)
        {
            PacketNumbers.Add(item);
        }
    }

    [RelayCommand]
    private async Task Export()
    {
        try
        {
            var desktop = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
            if (desktop?.MainWindow is not null)
            {
                var storageProvider = desktop.MainWindow.StorageProvider;
                var file = await storageProvider.SaveFilePickerAsync(new Avalonia.Platform.Storage.FilePickerSaveOptions
                {
                    Title = "Export Packet Numbers",
                    DefaultExtension = "txt",
                    FileTypeChoices = new List<Avalonia.Platform.Storage.FilePickerFileType>
                    {
                        new("Text Files") { Patterns = new[] { "*.txt" } },
                        new("CSV Files") { Patterns = new[] { "*.csv" } },
                        new("All Files") { Patterns = new[] { "*" } }
                    }
                });

                if (file is not null)
                {
                    var content = string.Join(Environment.NewLine, 
                        _allPacketNumbers.Select(p => p.Number.ToString()));
                    await using var stream = await file.OpenWriteAsync();
                    await using var writer = new System.IO.StreamWriter(stream);
                    await writer.WriteAsync(content);
                }
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"Export failed: {ex.Message}");
        }
    }

    [RelayCommand]
    private async Task Copy()
    {
        try
        {
            var numbers = string.Join(", ", _allPacketNumbers.Select(p => p.Number.ToString()));
            var desktop = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
            if (desktop?.MainWindow?.Clipboard is not null)
            {
                await desktop.MainWindow.Clipboard.SetTextAsync(numbers);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"Copy failed: {ex.Message}");
        }
    }
}