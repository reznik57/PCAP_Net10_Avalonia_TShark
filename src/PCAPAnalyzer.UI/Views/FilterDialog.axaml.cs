using System;
using System.Globalization;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Interactivity;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views;

public partial class FilterDialog : Window
{
    public FilterDialog()
    {
        InitializeComponent();
    }
    
    private void OnOkClick(object? sender, RoutedEventArgs e)
    {
        // Apply the filter and close the dialog
        if (DataContext is FilterViewModel viewModel)
        {
            viewModel.ApplyFilterCommand.Execute(null);
        }
        Close();
    }
    
    private void OnCancelClick(object? sender, RoutedEventArgs e)
    {
        Close();
    }
}

// Converter for displaying protocol names
public class ProtocolConverter : IValueConverter
{
    public static ProtocolConverter Instance { get; } = new();
    
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is null)
            return "All Protocols";
            
        return value.ToString();
    }
    
    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}