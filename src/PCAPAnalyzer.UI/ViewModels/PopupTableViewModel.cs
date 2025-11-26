using System.Collections;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class PopupTableViewModel : ObservableObject
    {
        private IEnumerable? _tableData;
        private string _filterText = string.Empty;

        [ObservableProperty] private IEnumerable? _filteredTableData;
        [ObservableProperty] private bool _isSourcesTable;
        [ObservableProperty] private bool _isDestinationsTable;
        [ObservableProperty] private bool _isConversationsTable;
        [ObservableProperty] private bool _isServicesTable;
        [ObservableProperty] private string _tableType = "";

        public IEnumerable? TableData
        {
            get => _tableData;
            set
            {
                if (SetProperty(ref _tableData, value))
                {
                    ApplyFilter();
                }
            }
        }

        public string FilterText
        {
            get => _filterText;
            set
            {
                if (SetProperty(ref _filterText, value))
                {
                    ApplyFilter();
                }
            }
        }

        public PopupTableViewModel(string tableType, IEnumerable data)
        {
            TableType = tableType;
            TableData = data;

            // Set visibility flags based on table type
            switch (tableType.ToLower())
            {
                case "sources":
                    IsSourcesTable = true;
                    break;
                case "destinations":
                    IsDestinationsTable = true;
                    break;
                case "conversations":
                    IsConversationsTable = true;
                    break;
                case "services":
                    IsServicesTable = true;
                    break;
            }
        }

        private void ApplyFilter()
        {
            if (TableData == null)
            {
                FilteredTableData = null;
                return;
            }

            if (string.IsNullOrWhiteSpace(FilterText))
            {
                FilteredTableData = TableData;
                return;
            }

            var filter = FilterText.ToLower();
            var items = new List<object>();

            foreach (var item in TableData)
            {
                if (item == null) continue;

                var matchFound = false;

                // Check all string properties for match
                foreach (var prop in item.GetType().GetProperties())
                {
                    if (prop.PropertyType == typeof(string))
                    {
                        var value = prop.GetValue(item) as string;
                        if (value != null && value.Contains(filter, System.StringComparison.OrdinalIgnoreCase))
                        {
                            matchFound = true;
                            break;
                        }
                    }
                    // Also check numeric properties converted to string
                    else if (prop.PropertyType == typeof(int) || prop.PropertyType == typeof(long) ||
                             prop.PropertyType == typeof(double) || prop.PropertyType == typeof(decimal))
                    {
                        var value = prop.GetValue(item)?.ToString();
                        if (value != null && value.Contains(filter, System.StringComparison.OrdinalIgnoreCase))
                        {
                            matchFound = true;
                            break;
                        }
                    }
                }

                if (matchFound)
                {
                    items.Add(item);
                }
            }

            FilteredTableData = items;
        }
    }
}