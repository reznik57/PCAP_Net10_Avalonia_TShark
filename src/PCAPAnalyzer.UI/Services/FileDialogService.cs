using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Implementation of IFileDialogService using Avalonia dialogs
    /// </summary>
    public class FileDialogService : IFileDialogService
    {
        private Window? GetMainWindow()
        {
            if (Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                return desktop.MainWindow;
            }
            return null;
        }

        public async Task<string?> OpenFileAsync(string title = "Open File", params FileDialogFilter[] filters)
        {
            var window = GetMainWindow();
            if (window == null) return null;

            var storageProvider = window.StorageProvider;
            if (storageProvider == null) return null;

            var options = new FilePickerOpenOptions
            {
                Title = title,
                AllowMultiple = false,
                FileTypeFilter = ConvertFilters(filters)
            };

            var result = await storageProvider.OpenFilePickerAsync(options);
            return result.Count > 0 ? result[0].Path.LocalPath : null;
        }

        public async Task<IEnumerable<string>> OpenFilesAsync(string title = "Open Files", params FileDialogFilter[] filters)
        {
            var window = GetMainWindow();
            if (window == null) return Enumerable.Empty<string>();

            var storageProvider = window.StorageProvider;
            if (storageProvider == null) return Enumerable.Empty<string>();

            var options = new FilePickerOpenOptions
            {
                Title = title,
                AllowMultiple = true,
                FileTypeFilter = ConvertFilters(filters)
            };

            var result = await storageProvider.OpenFilePickerAsync(options);
            return result.Select(f => f.Path.LocalPath).ToList();
        }

        public async Task<string?> SaveFileAsync(string title = "Save File", string defaultFileName = "", params FileDialogFilter[] filters)
        {
            var window = GetMainWindow();
            if (window == null) return null;

            var storageProvider = window.StorageProvider;
            if (storageProvider == null) return null;

            var options = new FilePickerSaveOptions
            {
                Title = title,
                SuggestedFileName = defaultFileName,
                FileTypeChoices = ConvertFilters(filters)
            };

            var result = await storageProvider.SaveFilePickerAsync(options);
            return result?.Path.LocalPath;
        }

        public async Task<string?> SelectFolderAsync(string title = "Select Folder")
        {
            var window = GetMainWindow();
            if (window == null) return null;

            var storageProvider = window.StorageProvider;
            if (storageProvider == null) return null;

            var options = new FolderPickerOpenOptions
            {
                Title = title,
                AllowMultiple = false
            };

            var result = await storageProvider.OpenFolderPickerAsync(options);
            return result.Count > 0 ? result[0].Path.LocalPath : null;
        }

        private static List<FilePickerFileType>? ConvertFilters(FileDialogFilter[] filters)
        {
            if (filters == null || filters.Length == 0)
                return null;

            return filters.Select(f => new FilePickerFileType(f.Name)
            {
                Patterns = f.Extensions.Select(ext => ext.StartsWith("*.", StringComparison.Ordinal) ? ext : $"*.{ext}").ToList()
            }).ToList();
        }
    }
}
