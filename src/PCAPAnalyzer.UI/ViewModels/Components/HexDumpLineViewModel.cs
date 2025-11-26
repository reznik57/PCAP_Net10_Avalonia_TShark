using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Represents a single row in the hex dump display.
/// Contains offset, hex bytes, and ASCII representation.
/// </summary>
public partial class HexDumpLineViewModel : ObservableObject
{
    [ObservableProperty] private string _offset = string.Empty;
    [ObservableProperty] private string _hexBytes = string.Empty;
    [ObservableProperty] private string _ascii = string.Empty;

    /// <summary>
    /// Creates a hex dump line
    /// </summary>
    public HexDumpLineViewModel(string offset, string hexBytes, string ascii)
    {
        Offset = offset;
        HexBytes = hexBytes;
        Ascii = ascii;
    }
}
