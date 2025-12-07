using System;
using System.Collections;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Collections
{
    /// <summary>
    /// A circular buffer that maintains a fixed-size window of the most recent items.
    /// Used for UI display only - does NOT affect data analysis or export.
    /// </summary>
    public class CircularBuffer<T> : IEnumerable<T>
    {
        private readonly T[] _buffer;
        private int _start;
        private int _end;
        private int _count;
        private readonly Lock _lock = new();
        
        public CircularBuffer(int capacity)
        {
            if (capacity <= 0)
                throw new ArgumentException("Capacity must be greater than 0", nameof(capacity));
                
            _buffer = new T[capacity];
        }
        
        public int Count
        {
            get { using (_lock.EnterScope()) return _count; }
        }
        
        public int Capacity => _buffer.Length;
        
        public void Add(T item)
        {
            using (_lock.EnterScope())
            {
                _buffer[_end] = item;
                _end = (_end + 1) % _buffer.Length;

                if (_count < _buffer.Length)
                {
                    _count++;
                }
                else
                {
                    // Buffer is full, overwrite oldest
                    _start = (_start + 1) % _buffer.Length;
                }
            }
        }
        
        public void AddRange(IEnumerable<T> items)
        {
            foreach (var item in items)
            {
                Add(item);
            }
        }
        
        public void Clear()
        {
            using (_lock.EnterScope())
            {
                _start = 0;
                _end = 0;
                _count = 0;
                Array.Clear(_buffer, 0, _buffer.Length);
            }
        }
        
        public T[] ToArray()
        {
            using (_lock.EnterScope())
            {
                var result = new T[_count];
                if (_count == 0) return result;

                if (_start < _end)
                {
                    Array.Copy(_buffer, _start, result, 0, _count);
                }
                else
                {
                    // Buffer wraps around
                    var firstPartLength = _buffer.Length - _start;
                    Array.Copy(_buffer, _start, result, 0, firstPartLength);
                    Array.Copy(_buffer, 0, result, firstPartLength, _end);
                }

                return result;
            }
        }
        
        public IEnumerator<T> GetEnumerator()
        {
            // Lock.Scope cannot cross yield boundaries, so snapshot array first
            var snapshot = ToArray();
            foreach (var item in snapshot)
            {
                yield return item;
            }
        }
        
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}