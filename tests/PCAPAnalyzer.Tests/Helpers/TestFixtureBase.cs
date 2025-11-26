using Xunit;
using Xunit.Abstractions;
using Microsoft.Extensions.Logging;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Base class for all test fixtures providing common setup and utilities.
/// </summary>
public abstract class TestFixtureBase : IDisposable
{
    protected ITestOutputHelper Output { get; }
    protected ILogger Logger { get; }
    protected MockDataGenerator MockData { get; }

    protected TestFixtureBase(ITestOutputHelper output)
    {
        Output = output;
        Logger = CreateLogger();
        MockData = new MockDataGenerator();
    }

    private ILogger CreateLogger()
    {
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddProvider(new XunitLoggerProvider(Output));
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        return loggerFactory.CreateLogger(GetType());
    }

    public virtual void Dispose()
    {
        // Cleanup code
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// xUnit logger provider that writes to test output.
/// </summary>
public class XunitLoggerProvider : ILoggerProvider
{
    private readonly ITestOutputHelper _output;

    public XunitLoggerProvider(ITestOutputHelper output)
    {
        _output = output;
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new XunitLogger(_output, categoryName);
    }

    public void Dispose() { }
}

public class XunitLogger : ILogger
{
    private readonly ITestOutputHelper _output;
    private readonly string _categoryName;

    public XunitLogger(ITestOutputHelper output, string categoryName)
    {
        _output = output;
        _categoryName = categoryName;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        => null;

    public bool IsEnabled(LogLevel logLevel)
        => logLevel >= LogLevel.Debug;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state,
        Exception? exception, Func<TState, Exception?, string> formatter)
    {
        try
        {
            _output.WriteLine($"[{logLevel}] {_categoryName}: {formatter(state, exception)}");
            if (exception != null)
            {
                _output.WriteLine($"Exception: {exception}");
            }
        }
        catch
        {
            // xUnit sometimes throws if test is already complete
        }
    }
}
