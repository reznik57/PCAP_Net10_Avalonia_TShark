using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Generic pagination component for tables. Eliminates duplicate pagination code.
/// Usage: Create instance for each paginated table, bind to navigation commands.
/// </summary>
public partial class PaginationViewModel<T> : ObservableObject where T : class
{
    private readonly Action? _onPageChanged;
    private List<T> _allItems = new();

    [ObservableProperty] private int _pageSize = 30;
    [ObservableProperty] private int _currentPage = 1;
    [ObservableProperty] private int _totalPages = 1;
    [ObservableProperty] private int _totalItems;
    [ObservableProperty] private ObservableCollection<T> _items = new();

    public PaginationViewModel(Action? onPageChanged = null)
    {
        _onPageChanged = onPageChanged;
    }

    /// <summary>
    /// Sets the source data and applies pagination.
    /// </summary>
    public void SetData(IEnumerable<T> items, Func<T, int, T>? rowNumberSetter = null)
    {
        _allItems = items.ToList();
        TotalItems = _allItems.Count;
        TotalPages = Math.Max(1, (int)Math.Ceiling((double)TotalItems / PageSize));
        CurrentPage = Math.Max(1, Math.Min(CurrentPage, TotalPages));
        ApplyPagination(rowNumberSetter);
    }

    /// <summary>
    /// Applies pagination to current data with optional row numbering.
    /// </summary>
    private void ApplyPagination(Func<T, int, T>? rowNumberSetter = null)
    {
        var skip = (CurrentPage - 1) * PageSize;
        var paged = _allItems.Skip(skip).Take(PageSize).ToList();

        // Apply row numbers if setter provided
        if (rowNumberSetter != null)
        {
            for (int i = 0; i < paged.Count; i++)
            {
                paged[i] = rowNumberSetter(paged[i], skip + i + 1);
            }
        }

        Items.Clear();
        foreach (var item in paged)
        {
            Items.Add(item);
        }

        _onPageChanged?.Invoke();
    }

    [RelayCommand]
    public void NextPage()
    {
        if (CurrentPage < TotalPages)
        {
            CurrentPage++;
            ApplyPagination();
        }
    }

    [RelayCommand]
    public void PreviousPage()
    {
        if (CurrentPage > 1)
        {
            CurrentPage--;
            ApplyPagination();
        }
    }

    [RelayCommand]
    public void FirstPage()
    {
        CurrentPage = 1;
        ApplyPagination();
    }

    [RelayCommand]
    public void LastPage()
    {
        CurrentPage = TotalPages;
        ApplyPagination();
    }

    [RelayCommand]
    public void JumpForward10()
    {
        CurrentPage = Math.Min(CurrentPage + 10, TotalPages);
        ApplyPagination();
    }

    [RelayCommand]
    public void JumpBackward10()
    {
        CurrentPage = Math.Max(CurrentPage - 10, 1);
        ApplyPagination();
    }

    public void SetPageSize(int pageSize)
    {
        PageSize = pageSize;
        CurrentPage = 1;
        TotalPages = Math.Max(1, (int)Math.Ceiling((double)TotalItems / PageSize));
        ApplyPagination();
    }
}
