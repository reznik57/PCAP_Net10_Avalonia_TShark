using System.Windows.Input;
using Avalonia.Controls;
using Avalonia.Input;

namespace PCAPAnalyzer.UI.Views.Controls;

public partial class FilterPanelControl : UserControl
{
    public FilterPanelControl()
    {
        InitializeComponent();
    }

    private void FilterTextBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            // Get ApplyFiltersCommand from DataContext using reflection
            // This works with any ViewModel that has ApplyFiltersCommand
            var dataContext = DataContext;
            if (dataContext == null) return;

            var commandProperty = dataContext.GetType().GetProperty("ApplyFiltersCommand");
            if (commandProperty?.GetValue(dataContext) is ICommand command && command.CanExecute(null))
            {
                command.Execute(null);
                e.Handled = true;
            }
        }
    }
}
