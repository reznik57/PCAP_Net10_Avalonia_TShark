using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;

namespace PCAPAnalyzer.UI.Helpers
{
    /// <summary>
    /// Throttles actions to prevent excessive updates while ensuring all data is processed
    /// </summary>
    public class ThrottledAction
    {
        private readonly TimeSpan _throttleInterval;
        private readonly Action _action;
        private readonly DispatcherTimer _timer;
        private bool _isPending;
        private readonly Lock _lock = new();
        
        public ThrottledAction(TimeSpan throttleInterval, Action action)
        {
            ArgumentNullException.ThrowIfNull(action);
            _throttleInterval = throttleInterval;
            _action = action;
            
            _timer = new DispatcherTimer
            {
                Interval = throttleInterval
            };
            _timer.Tick += OnTimerTick;
        }
        
        /// <summary>
        /// Request the action to be executed. Multiple calls will be throttled.
        /// </summary>
        public void Request()
        {
            using (_lock.EnterScope())
            {
                _isPending = true;
                if (!_timer.IsEnabled)
                {
                    _timer.Start();
                }
            }
        }
        
        private void OnTimerTick(object? sender, EventArgs e)
        {
            using (_lock.EnterScope())
            {
                _timer.Stop();
                if (_isPending)
                {
                    _isPending = false;
                    _action();
                }
            }
        }
        
        public void Stop()
        {
            using (_lock.EnterScope())
            {
                _timer.Stop();
                _isPending = false;
            }
        }
    }
    
    /// <summary>
    /// Async version of ThrottledAction
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "CTS is disposed in ExecuteAsync method")]
    public class ThrottledAsyncAction
    {
        private readonly TimeSpan _throttleInterval;
        private readonly Func<Task> _action;
        private CancellationTokenSource? _cts;
        private readonly Lock _lock = new();
        
        public ThrottledAsyncAction(TimeSpan throttleInterval, Func<Task> action)
        {
            ArgumentNullException.ThrowIfNull(action);
            _throttleInterval = throttleInterval;
            _action = action;
        }
        
        /// <summary>
        /// Request the async action to be executed. Multiple calls will be throttled.
        /// </summary>
        public async Task RequestAsync()
        {
            CancellationTokenSource cts;

            using (_lock.EnterScope())
            {
                _cts?.Cancel();
                _cts = new();
                cts = _cts;
            }
            
            try
            {
                await Task.Delay(_throttleInterval, cts.Token).ConfigureAwait(false);
                
                if (!cts.Token.IsCancellationRequested)
                {
                    await _action().ConfigureAwait(false);
                }
            }
            catch (TaskCanceledException)
            {
                // Expected when throttling
            }
        }
        
        public void Cancel()
        {
            using (_lock.EnterScope())
            {
                _cts?.Cancel();
            }
        }
    }
}