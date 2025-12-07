using System.Collections.Generic;
using System.Threading.Tasks;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Service for showing file dialogs.
    /// Abstracts platform-specific file dialog functionality for testability.
    /// </summary>
    public interface IFileDialogService
    {
        /// <summary>
        /// Show an open file dialog
        /// </summary>
        /// <param name="title">Dialog title</param>
        /// <param name="filters">File type filters</param>
        /// <returns>Selected file path, or null if cancelled</returns>
        Task<string?> OpenFileAsync(string title = "Open File", params FileDialogFilter[] filters);

        /// <summary>
        /// Show an open multiple files dialog
        /// </summary>
        /// <param name="title">Dialog title</param>
        /// <param name="filters">File type filters</param>
        /// <returns>Selected file paths, or empty if cancelled</returns>
        Task<IEnumerable<string>> OpenFilesAsync(string title = "Open Files", params FileDialogFilter[] filters);

        /// <summary>
        /// Show a save file dialog
        /// </summary>
        /// <param name="title">Dialog title</param>
        /// <param name="defaultFileName">Default file name</param>
        /// <param name="filters">File type filters</param>
        /// <returns>Selected file path, or null if cancelled</returns>
        Task<string?> SaveFileAsync(string title = "Save File", string defaultFileName = "", params FileDialogFilter[] filters);

        /// <summary>
        /// Show a folder selection dialog
        /// </summary>
        /// <param name="title">Dialog title</param>
        /// <returns>Selected folder path, or null if cancelled</returns>
        Task<string?> SelectFolderAsync(string title = "Select Folder");
    }

    /// <summary>
    /// File type filter for dialogs
    /// </summary>
    public class FileDialogFilter
    {
        public string Name { get; set; } = string.Empty;
        public List<string> Extensions { get; set; } = [];

        public FileDialogFilter(string name, params string[] extensions)
        {
            Name = name;
            Extensions = new List<string>(extensions);
        }
    }
}
