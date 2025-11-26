using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Base class for ViewModels that need pagination functionality.
    /// Provides common pagination logic to reduce code duplication.
    /// </summary>
    /// <typeparam name="T">The type of items to paginate</typeparam>
    public abstract partial class PaginatedViewModel<T> : ObservableObject
    {
        private List<T> _allItems = new();

        [ObservableProperty]
        private ObservableCollection<T> _pagedItems = new();

        [ObservableProperty]
        private int _currentPage = 1;

        [ObservableProperty]
        private int _pageSize = 25;

        [ObservableProperty]
        private int _totalPages;

        [ObservableProperty]
        private int _totalItems;

        [ObservableProperty]
        private bool _canGoToNextPage;

        [ObservableProperty]
        private bool _canGoToPreviousPage;

        [ObservableProperty]
        private string _pageInfo = string.Empty;

        /// <summary>
        /// Set all items and refresh pagination
        /// </summary>
        public virtual void SetItems(List<T> items)
        {
            _allItems = items ?? new List<T>();
            TotalItems = _allItems.Count;
            CurrentPage = 1;
            UpdatePagination();
        }

        /// <summary>
        /// Set all items and refresh pagination (IEnumerable overload)
        /// </summary>
        public virtual void SetItems(IEnumerable<T> items)
        {
            SetItems(items?.ToList() ?? new List<T>());
        }

        /// <summary>
        /// Get all items (unpaginated)
        /// </summary>
        public IReadOnlyList<T> GetAllItems() => _allItems.AsReadOnly();

        /// <summary>
        /// Update pagination - override for custom logic
        /// </summary>
        protected virtual void UpdatePagination()
        {
            if (_allItems == null || _allItems.Count == 0)
            {
                TotalPages = 0;
                TotalItems = 0;
                PagedItems.Clear();
                CanGoToNextPage = false;
                CanGoToPreviousPage = false;
                PageInfo = "No items";
                return;
            }

            TotalPages = (int)Math.Ceiling((double)TotalItems / PageSize);

            // Ensure current page is valid
            if (CurrentPage < 1)
                CurrentPage = 1;
            if (CurrentPage > TotalPages)
                CurrentPage = TotalPages;

            // Calculate pagination
            var skip = (CurrentPage - 1) * PageSize;
            var pageItems = _allItems.Skip(skip).Take(PageSize).ToList();

            // Update collection
            PagedItems.Clear();
            foreach (var item in pageItems)
            {
                PagedItems.Add(item);
            }

            // Update navigation state
            CanGoToNextPage = CurrentPage < TotalPages;
            CanGoToPreviousPage = CurrentPage > 1;

            // Update page info
            var startItem = skip + 1;
            var endItem = Math.Min(skip + PageSize, TotalItems);
            PageInfo = $"{startItem}-{endItem} of {TotalItems}";
        }

        [RelayCommand(CanExecute = nameof(CanGoToPreviousPage))]
        private void GoToPreviousPage()
        {
            if (CurrentPage > 1)
            {
                CurrentPage--;
                UpdatePagination();
            }
        }

        [RelayCommand(CanExecute = nameof(CanGoToNextPage))]
        private void GoToNextPage()
        {
            if (CurrentPage < TotalPages)
            {
                CurrentPage++;
                UpdatePagination();
            }
        }

        [RelayCommand]
        private void GoToFirstPage()
        {
            if (CurrentPage != 1)
            {
                CurrentPage = 1;
                UpdatePagination();
            }
        }

        [RelayCommand]
        private void GoToLastPage()
        {
            if (CurrentPage != TotalPages && TotalPages > 0)
            {
                CurrentPage = TotalPages;
                UpdatePagination();
            }
        }

        [RelayCommand]
        private void GoToPage(int pageNumber)
        {
            if (pageNumber >= 1 && pageNumber <= TotalPages)
            {
                CurrentPage = pageNumber;
                UpdatePagination();
            }
        }

        partial void OnPageSizeChanged(int value)
        {
            if (value > 0)
            {
                UpdatePagination();
            }
        }

        partial void OnCurrentPageChanged(int value)
        {
            // Update command states
            GoToPreviousPageCommand.NotifyCanExecuteChanged();
            GoToNextPageCommand.NotifyCanExecuteChanged();
        }
    }
}
