using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Reusable pagination component for tabular data.
/// Eliminates duplicate pagination logic across ViewModels.
/// </summary>
public partial class PaginationViewModel : ObservableObject
{
    private readonly Action _onPageChanged;

    [ObservableProperty] private int _pageSize = 30;
    [ObservableProperty] private int _currentPage = 1;
    [ObservableProperty] private int _totalPages = 1;
    [ObservableProperty] private int _totalItems;

    /// <summary>
    /// Number of items to skip for current page
    /// </summary>
    public int Skip => (CurrentPage - 1) * PageSize;

    /// <summary>
    /// Whether there is a previous page
    /// </summary>
    public bool HasPreviousPage => CurrentPage > 1;

    /// <summary>
    /// Whether there is a next page
    /// </summary>
    public bool HasNextPage => CurrentPage < TotalPages;

    /// <summary>
    /// Display text for current position (e.g., "Page 1 of 10")
    /// </summary>
    public string PageInfo => $"Page {CurrentPage} of {TotalPages}";

    /// <summary>
    /// Display text for item range (e.g., "1-30 of 150")
    /// </summary>
    public string ItemRange
    {
        get
        {
            var start = Skip + 1;
            var end = Math.Min(Skip + PageSize, TotalItems);
            return $"{start}-{end} of {TotalItems}";
        }
    }

    public PaginationViewModel(Action onPageChanged)
    {
        _onPageChanged = onPageChanged ?? throw new ArgumentNullException(nameof(onPageChanged));
    }

    /// <summary>
    /// Updates pagination state based on total items count.
    /// Recalculates total pages and clamps current page.
    /// </summary>
    public void UpdateFromItemCount(int totalItems)
    {
        TotalItems = totalItems;
        TotalPages = Math.Max(1, (int)Math.Ceiling((double)totalItems / PageSize));
        CurrentPage = Math.Max(1, Math.Min(CurrentPage, TotalPages));

        OnPropertyChanged(nameof(Skip));
        OnPropertyChanged(nameof(HasPreviousPage));
        OnPropertyChanged(nameof(HasNextPage));
        OnPropertyChanged(nameof(PageInfo));
        OnPropertyChanged(nameof(ItemRange));
    }

    public void NextPage()
    {
        if (CurrentPage < TotalPages)
        {
            CurrentPage++;
            NotifyAndCallback();
        }
    }

    public void PreviousPage()
    {
        if (CurrentPage > 1)
        {
            CurrentPage--;
            NotifyAndCallback();
        }
    }

    public void FirstPage()
    {
        if (CurrentPage != 1)
        {
            CurrentPage = 1;
            NotifyAndCallback();
        }
    }

    public void LastPage()
    {
        if (CurrentPage != TotalPages)
        {
            CurrentPage = TotalPages;
            NotifyAndCallback();
        }
    }

    public void JumpForward(int pages = 10)
    {
        var newPage = Math.Min(CurrentPage + pages, TotalPages);
        if (newPage != CurrentPage)
        {
            CurrentPage = newPage;
            NotifyAndCallback();
        }
    }

    public void JumpBackward(int pages = 10)
    {
        var newPage = Math.Max(CurrentPage - pages, 1);
        if (newPage != CurrentPage)
        {
            CurrentPage = newPage;
            NotifyAndCallback();
        }
    }

    public void SetPageSize(int pageSize)
    {
        if (pageSize != PageSize && pageSize > 0)
        {
            PageSize = pageSize;
            CurrentPage = 1; // Reset to first page
            UpdateFromItemCount(TotalItems);
            NotifyAndCallback();
        }
    }

    private void NotifyAndCallback()
    {
        OnPropertyChanged(nameof(Skip));
        OnPropertyChanged(nameof(HasPreviousPage));
        OnPropertyChanged(nameof(HasNextPage));
        OnPropertyChanged(nameof(PageInfo));
        OnPropertyChanged(nameof(ItemRange));
        _onPageChanged();
    }
}
