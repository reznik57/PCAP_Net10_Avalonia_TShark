using System;
using System.Threading;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Throttles event invocations to prevent UI saturation during high-frequency events
    /// </summary>
    /// <typeparam name="T">Type of event args to throttle</typeparam>
    public sealed class EventThrottler<T> : IDisposable where T : EventArgs
    {
        private readonly TimeSpan _throttleInterval;
        private readonly Timer _timer;
        private T? _pendingEventArgs;
        private object? _pendingSender;
        private bool _hasPendingEvent;
        private readonly Lock _lock = new();
        private bool _disposed;

        /// <summary>
        /// Event raised when throttled event should be invoked
        /// </summary>
        public event EventHandler<T>? ThrottledEvent;

        /// <summary>
        /// Initializes a new event throttler
        /// </summary>
        /// <param name="throttleInterval">Minimum interval between event invocations</param>
        public EventThrottler(TimeSpan throttleInterval)
        {
            _throttleInterval = throttleInterval;
            _timer = new Timer(OnTimerTick, null, throttleInterval, throttleInterval);
        }

        /// <summary>
        /// Enqueues an event for throttled invocation
        /// </summary>
        /// <param name="sender">Event sender</param>
        /// <param name="eventArgs">Event arguments</param>
        public void Enqueue(object? sender, T eventArgs)
        {
            if (_disposed)
                return;

            using (_lock.EnterScope())
            {
                _pendingSender = sender;
                _pendingEventArgs = eventArgs;
                _hasPendingEvent = true;
            }
        }

        /// <summary>
        /// Timer callback that invokes pending events
        /// </summary>
        private void OnTimerTick(object? state)
        {
            if (_disposed)
                return;

            T? argsToRaise = null;
            object? senderToRaise = null;

            using (_lock.EnterScope())
            {
                if (_hasPendingEvent)
                {
                    senderToRaise = _pendingSender;
                    argsToRaise = _pendingEventArgs;
                    _hasPendingEvent = false;
                    _pendingEventArgs = default;
                    _pendingSender = null;
                }
            }

            if (argsToRaise is not null)
            {
                try
                {
                    ThrottledEvent?.Invoke(senderToRaise, argsToRaise);
                }
                catch
                {
                    // Suppress exceptions in event handlers to prevent timer disruption
                }
            }
        }

        /// <summary>
        /// Disposes the throttler and stops the timer
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _timer?.Dispose();
        }
    }
}
