using System.Collections.ObjectModel;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Specialized pagination view model for Security Threats.
    /// Extends PaginatedViewModel with page number support.
    /// </summary>
    public partial class SecurityThreatPaginationViewModel : PaginatedViewModel<SecurityThreatItemViewModel>
    {
        private ObservableCollection<int> _pageNumbers = new();

        public ObservableCollection<int> PageNumbers => _pageNumbers;

        protected override void UpdatePagination()
        {
            base.UpdatePagination();
            UpdatePageNumbers();
        }

        private void UpdatePageNumbers()
        {
            _pageNumbers.Clear();

            if (TotalPages == 0) return;

            // Show page numbers around current page (current - 2 to current + 2)
            var startPage = Math.Max(1, CurrentPage - 2);
            var endPage = Math.Min(TotalPages, CurrentPage + 2);

            for (int i = startPage; i <= endPage; i++)
            {
                _pageNumbers.Add(i);
            }
        }
    }
}
