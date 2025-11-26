using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Avalonia.ReactiveUI;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Monitoring;
using PCAPAnalyzer.UI.Views;
using ReactiveUI;
using System;
using System.Reactive.Concurrency;
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
            if (System.Threading.SynchronizationContext.Current == null)
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
            
            if (ex.InnerException != null)
            {
                DebugLogger.Log($"[App] Inner exception: {ex.InnerException.Message}");
                DebugLogger.Log($"[App] Inner stack trace: {ex.InnerException.StackTrace}");
            }
            
            throw;
        }
    }
}
