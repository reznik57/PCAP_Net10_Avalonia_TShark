using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Avalonia.ReactiveUI;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Monitoring;
using PCAPAnalyzer.Core.Services.Cache;
using PCAPAnalyzer.UI.Views;
using ReactiveUI;
using System;
using System.Reactive;
using System.Reactive.Concurrency;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI;

public partial class App : Application
{
    public static IServiceProvider Services { get; private set; } = null!;

    public override void Initialize()
    {
        try
        {
            DebugLogger.Log("[App] Initializing XAML...");
            
            // Configure ReactiveUI to use Avalonia's UI thread scheduler
            // This ensures all ReactiveCommand operations happen on UI thread
            RxApp.MainThreadScheduler = AvaloniaScheduler.Instance;
            
            AvaloniaXamlLoader.Load(this);
            DebugLogger.Log("[App] XAML loaded successfully");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[App] Error loading XAML: {ex.Message}");
            DebugLogger.Log($"[App] Stack trace: {ex.StackTrace}");
            throw;
        }
    }

    public override void OnFrameworkInitializationCompleted()
    {
        // Global exception handlers for Windows 11 stability
        SetupGlobalExceptionHandlers();

        try
        {
            // ✅ FORCE DEBUG MODE: Set environment variable if not already set
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PCAP_DEBUG")))
            {
                Environment.SetEnvironmentVariable("PCAP_DEBUG", "1");
                Console.WriteLine("⚙️  Debug mode enabled (PCAP_DEBUG=1)");
            }

            DebugLogger.Log("[App] Framework initialization started...");

            Services ??= ServiceConfiguration.ConfigureServices();

            // Initialize health monitoring
            HealthMonitor.Initialize();

            // Set up synchronization context for async operations
            if (System.Threading.SynchronizationContext.Current is null)
            {
                System.Threading.SynchronizationContext.SetSynchronizationContext(
                    new AvaloniaSynchronizationContext());
            }

            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                DebugLogger.Log("[App] Creating MainWindow...");
                var mainWindowViewModel = Services.GetRequiredService<ViewModels.MainWindowViewModel>();
                desktop.MainWindow = new MainWindow(mainWindowViewModel);
                DebugLogger.Log("[App] MainWindow created successfully");

                // Set window properties for better stability
                desktop.MainWindow.WindowStartupLocation = Avalonia.Controls.WindowStartupLocation.CenterScreen;
                desktop.MainWindow.CanResize = true;

                DebugLogger.Log($"[App] Window Title: {desktop.MainWindow.Title}");
                DebugLogger.Log($"[App] Window Size: {desktop.MainWindow.Width}x{desktop.MainWindow.Height}");

                // Clear old analysis cache on startup (fire-and-forget, non-blocking)
                _ = ClearOldCacheOnStartupAsync();
            }
            else
            {
                DebugLogger.Log("[App] ApplicationLifetime is not IClassicDesktopStyleApplicationLifetime");
            }

            base.OnFrameworkInitializationCompleted();
            DebugLogger.Log("[App] Framework initialization completed");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[App] Error in OnFrameworkInitializationCompleted: {ex.Message}");
            DebugLogger.Log($"[App] Stack trace: {ex.StackTrace}");

            if (ex.InnerException is not null)
            {
                DebugLogger.Log($"[App] Inner exception: {ex.InnerException.Message}");
                DebugLogger.Log($"[App] Inner stack trace: {ex.InnerException.StackTrace}");
            }

            throw;
        }
    }

    /// <summary>
    /// Sets up global exception handlers to prevent crashes from unhandled async exceptions.
    /// Critical for Windows 11 stability - catches exceptions that escape async void handlers.
    /// </summary>
    private static void SetupGlobalExceptionHandlers()
    {
        // Handle exceptions on non-UI threads
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            var ex = e.ExceptionObject as Exception;
            DebugLogger.Log($"[FATAL] Unhandled exception: {ex?.Message}");
            DebugLogger.Log($"[FATAL] Stack trace: {ex?.StackTrace}");
            // Let Windows Error Reporting handle true crashes
        };

        // Handle unobserved Task exceptions (fire-and-forget async operations)
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            DebugLogger.Log($"[ASYNC-ERROR] Unobserved task exception: {e.Exception.Message}");
            foreach (var inner in e.Exception.InnerExceptions)
            {
                DebugLogger.Log($"[ASYNC-ERROR] Inner: {inner.Message}");
            }
            e.SetObserved(); // Prevent app crash, we've logged it
        };

        // Handle Avalonia UI thread exceptions via ReactiveUI
        RxApp.DefaultExceptionHandler = Observer.Create<Exception>(ex =>
        {
            DebugLogger.Log($"[UI-ERROR] ReactiveUI exception: {ex.Message}");
            DebugLogger.Log($"[UI-ERROR] Stack trace: {ex.StackTrace}");
        });

        DebugLogger.Log("[App] Global exception handlers registered");
    }

    /// <summary>
    /// Clears all old analysis cache entries on startup.
    /// Runs asynchronously to avoid blocking app startup.
    /// </summary>
    private static async Task ClearOldCacheOnStartupAsync()
    {
        try
        {
            DebugLogger.Log("[App] Clearing old analysis cache on startup...");
            var cacheService = Services.GetService<IAnalysisCacheService>();
            if (cacheService is not null)
            {
                var deletedCount = await cacheService.ClearAllCacheAsync();
                DebugLogger.Log($"[App] Cleared {deletedCount} old cache entries on startup");
            }
            else
            {
                DebugLogger.Log("[App] Cache service not available - skipping cleanup");
            }
        }
        catch (Exception ex)
        {
            // Don't fail startup if cache cleanup fails
            DebugLogger.Log($"[App] Warning: Cache cleanup failed: {ex.Message}");
        }
    }
}
