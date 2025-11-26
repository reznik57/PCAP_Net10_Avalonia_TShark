using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Base class for ViewModel tests with common setup and utilities
/// </summary>
public abstract class ViewModelTestBase<TViewModel> : IDisposable where TViewModel : class
{
    protected MockServiceFactory MockFactory { get; }
    protected ServiceProvider ServiceProvider { get; }
    protected TViewModel? ViewModel { get; set; }

    protected ViewModelTestBase()
    {
        MockFactory = new MockServiceFactory();
        ServiceProvider = ConfigureServices().BuildServiceProvider();
    }

    /// <summary>
    /// Override to configure services for the ViewModel
    /// </summary>
    protected virtual ServiceCollection ConfigureServices()
    {
        return MockFactory.CreateServiceCollection();
    }

    /// <summary>
    /// Get a service from the DI container
    /// </summary>
    protected T GetService<T>() where T : notnull
    {
        return ServiceProvider.GetRequiredService<T>();
    }

    /// <summary>
    /// Assert that a property change event was raised
    /// </summary>
    protected void AssertPropertyChanged(object viewModel, string propertyName, Action action)
    {
        var propertyChanged = false;
        if (viewModel is System.ComponentModel.INotifyPropertyChanged notifyPropertyChanged)
        {
            notifyPropertyChanged.PropertyChanged += (sender, args) =>
            {
                if (args.PropertyName == propertyName)
                {
                    propertyChanged = true;
                }
            };

            action();

            Assert.True(propertyChanged, $"Property '{propertyName}' did not raise PropertyChanged event");
        }
        else
        {
            throw new InvalidOperationException($"{viewModel.GetType().Name} does not implement INotifyPropertyChanged");
        }
    }

    public virtual void Dispose()
    {
        ServiceProvider?.Dispose();
        GC.SuppressFinalize(this);
    }
}
