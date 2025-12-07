using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace PCAPAnalyzer.UI.Collections
{
    /// <summary>
    /// An ObservableCollection that supports batch updates to reduce UI notifications.
    /// This improves performance when adding many items at once.
    /// </summary>
    public class BatchObservableCollection<T> : ObservableCollection<T>
    {
        private bool _suppressNotification;
        private bool _notificationPending;
        
        /// <summary>
        /// Begin a batch update. UI notifications are suspended until EndBatchUpdate is called.
        /// </summary>
        public void BeginBatchUpdate()
        {
            _suppressNotification = true;
        }
        
        /// <summary>
        /// End a batch update and send a single Reset notification to update the UI.
        /// </summary>
        public void EndBatchUpdate()
        {
            _suppressNotification = false;
            if (_notificationPending)
            {
                OnCollectionChanged(new NotifyCollectionChangedEventArgs(
                    NotifyCollectionChangedAction.Reset));
                _notificationPending = false;
            }
        }
        
        /// <summary>
        /// Add multiple items with a single UI notification.
        /// </summary>
        public void AddRange(IEnumerable<T> items)
        {
            if (items is null)
                throw new ArgumentNullException(nameof(items));
                
            BeginBatchUpdate();
            try
            {
                foreach (var item in items)
                {
                    Add(item);
                }
            }
            finally
            {
                EndBatchUpdate();
            }
        }
        
        /// <summary>
        /// Replace all items with new collection efficiently.
        /// </summary>
        public void ReplaceAll(IEnumerable<T> items)
        {
            if (items is null)
                throw new ArgumentNullException(nameof(items));
                
            BeginBatchUpdate();
            try
            {
                Clear();
                foreach (var item in items)
                {
                    Add(item);
                }
            }
            finally
            {
                EndBatchUpdate();
            }
        }
        
        protected override void OnCollectionChanged(NotifyCollectionChangedEventArgs e)
        {
            if (_suppressNotification)
            {
                _notificationPending = true;
                return;
            }
            
            base.OnCollectionChanged(e);
        }
        
        protected override void OnPropertyChanged(PropertyChangedEventArgs e)
        {
            if (!_suppressNotification)
            {
                base.OnPropertyChanged(e);
            }
        }
    }
}