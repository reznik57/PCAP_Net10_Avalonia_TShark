using System.Threading.Tasks;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Service for capturing screenshots.
    /// Abstracts screenshot functionality for testability and separation of concerns.
    /// </summary>
    public interface IScreenshotService
    {
        /// <summary>
        /// Capture a screenshot of the current tab/view
        /// </summary>
        /// <param name="viewName">Optional view name for the filename</param>
        /// <returns>True if screenshot was saved successfully</returns>
        Task<bool> CaptureCurrentViewAsync(string? viewName = null);

        /// <summary>
        /// Capture a screenshot with a custom filename
        /// </summary>
        /// <param name="fileName">Filename (without extension)</param>
        /// <returns>True if screenshot was saved successfully</returns>
        Task<bool> CaptureWithFilenameAsync(string fileName);

        /// <summary>
        /// Get the path where screenshots are saved
        /// </summary>
        string GetScreenshotDirectory();
    }
}
