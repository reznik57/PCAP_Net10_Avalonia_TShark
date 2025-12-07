using System;
using System.Collections.Concurrent;
using System.Threading;

namespace PCAPAnalyzer.Core.Performance
{
    /// <summary>
    /// High-performance object pool to reduce GC pressure and allocation overhead
    /// Implements lock-free pooling with configurable size limits
    /// </summary>
    /// <typeparam name="T">Type of objects to pool</typeparam>
    public sealed class ObjectPool<T> : IDisposable where T : class
    {
        private readonly ConcurrentBag<T> _objects;
        private readonly Func<T> _objectFactory;
        private readonly Action<T>? _resetAction;
        private readonly int _maxPoolSize;
        private int _currentCount;
        private bool _disposed;

        // Statistics
        private long _totalCreated;
        private long _totalRented;
        private long _totalReturned;
        private long _totalDiscarded;

        /// <summary>
        /// Gets pool statistics
        /// </summary>
        public ObjectPoolStatistics Statistics => new()
        {
            CurrentPoolSize = _currentCount,
            MaxPoolSize = _maxPoolSize,
            TotalCreated = Interlocked.Read(ref _totalCreated),
            TotalRented = Interlocked.Read(ref _totalRented),
            TotalReturned = Interlocked.Read(ref _totalReturned),
            TotalDiscarded = Interlocked.Read(ref _totalDiscarded),
            AvailableCount = _objects.Count
        };

        /// <summary>
        /// Initializes a new object pool
        /// </summary>
        /// <param name="objectFactory">Factory function to create new objects</param>
        /// <param name="resetAction">Optional action to reset objects before returning to pool</param>
        /// <param name="maxPoolSize">Maximum number of objects to keep in pool</param>
        /// <param name="preAllocate">Number of objects to pre-allocate</param>
        public ObjectPool(
            Func<T> objectFactory,
            Action<T>? resetAction = null,
            int maxPoolSize = 100,
            int preAllocate = 0)
        {
            _objectFactory = objectFactory ?? throw new ArgumentNullException(nameof(objectFactory));
            _resetAction = resetAction;
            _maxPoolSize = maxPoolSize > 0 ? maxPoolSize : 100;
            _objects = new ConcurrentBag<T>();

            // Pre-allocate objects if requested
            for (int i = 0; i < Math.Min(preAllocate, maxPoolSize); i++)
            {
                var obj = _objectFactory();
                _objects.Add(obj);
                Interlocked.Increment(ref _totalCreated);
                Interlocked.Increment(ref _currentCount);
            }
        }

        /// <summary>
        /// Rents an object from the pool or creates a new one
        /// </summary>
        /// <returns>An object from the pool</returns>
        public T Rent()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ObjectPool<T>));

            Interlocked.Increment(ref _totalRented);

            if (_objects.TryTake(out T? obj))
            {
                Interlocked.Decrement(ref _currentCount);
                return obj;
            }

            // Pool is empty, create new object
            Interlocked.Increment(ref _totalCreated);
            return _objectFactory();
        }

        /// <summary>
        /// Returns an object to the pool
        /// </summary>
        /// <param name="obj">Object to return</param>
        public void Return(T obj)
        {
            if (_disposed || obj is null)
            {
                Interlocked.Increment(ref _totalDiscarded);
                return;
            }

            Interlocked.Increment(ref _totalReturned);

            // Check if pool is full
            if (_currentCount >= _maxPoolSize)
            {
                Interlocked.Increment(ref _totalDiscarded);
                // Let GC collect it
                if (obj is IDisposable disposable)
                {
                    disposable.Dispose();
                }
                return;
            }

            // Reset object if reset action provided
            try
            {
                _resetAction?.Invoke(obj);
            }
            catch
            {
                // If reset fails, discard the object
                Interlocked.Increment(ref _totalDiscarded);
                if (obj is IDisposable disposable)
                {
                    disposable.Dispose();
                }
                return;
            }

            // Return to pool
            _objects.Add(obj);
            Interlocked.Increment(ref _currentCount);
        }

        /// <summary>
        /// Clears all objects from the pool
        /// </summary>
        public void Clear()
        {
            while (_objects.TryTake(out T? obj))
            {
                if (obj is IDisposable disposable)
                {
                    disposable.Dispose();
                }
                Interlocked.Decrement(ref _currentCount);
            }
        }

        /// <summary>
        /// Resets pool statistics
        /// </summary>
        public void ResetStatistics()
        {
            Interlocked.Exchange(ref _totalCreated, _objects.Count);
            Interlocked.Exchange(ref _totalRented, 0);
            Interlocked.Exchange(ref _totalReturned, 0);
            Interlocked.Exchange(ref _totalDiscarded, 0);
        }

        public void Dispose()
        {
            if (_disposed) return;

            Clear();
            _disposed = true;
        }
    }

    /// <summary>
    /// Pooled object wrapper with automatic return on dispose
    /// </summary>
    /// <typeparam name="T">Type of pooled object</typeparam>
    public sealed class PooledObject<T> : IDisposable where T : class
    {
        private readonly ObjectPool<T> _pool;
        private T? _object;
        private bool _disposed;

        public T Object
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(PooledObject<T>));
                return _object ?? throw new InvalidOperationException("Object has been returned to pool");
            }
        }

        internal PooledObject(ObjectPool<T> pool, T obj)
        {
            _pool = pool;
            _object = obj;
        }

        public void Dispose()
        {
            if (_disposed) return;

            if (_object is not null)
            {
                _pool.Return(_object);
                _object = null;
            }

            _disposed = true;
        }
    }

    /// <summary>
    /// Extension methods for object pool
    /// </summary>
    public static class ObjectPoolExtensions
    {
        /// <summary>
        /// Rents an object with automatic return on dispose
        /// </summary>
        public static PooledObject<T> RentScoped<T>(this ObjectPool<T> pool) where T : class
        {
            var obj = pool.Rent();
            return new PooledObject<T>(pool, obj);
        }
    }

    /// <summary>
    /// Object pool statistics
    /// </summary>
    public sealed class ObjectPoolStatistics
    {
        public int CurrentPoolSize { get; init; }
        public int MaxPoolSize { get; init; }
        public long TotalCreated { get; init; }
        public long TotalRented { get; init; }
        public long TotalReturned { get; init; }
        public long TotalDiscarded { get; init; }
        public int AvailableCount { get; init; }

        public double ReuseRate => TotalRented > 0
            ? ((TotalRented - TotalCreated) * 100.0) / TotalRented
            : 0;

        public override string ToString()
        {
            return $"Pool: {CurrentPoolSize}/{MaxPoolSize}, " +
                   $"Created: {TotalCreated}, Rented: {TotalRented}, " +
                   $"Returned: {TotalReturned}, Discarded: {TotalDiscarded}, " +
                   $"Reuse Rate: {ReuseRate:F2}%";
        }
    }

    /// <summary>
    /// Specialized pool for byte arrays
    /// </summary>
    public sealed class ByteArrayPool
    {
        private readonly ConcurrentBag<byte[]>[] _buckets;
        private readonly int[] _bucketSizes;
        private readonly int _maxArrayLength;
        private const int BucketCount = 17; // Support sizes up to 1MB

        public ByteArrayPool(int maxArrayLength = 1024 * 1024)
        {
            _maxArrayLength = maxArrayLength;
            _buckets = new ConcurrentBag<byte[]>[BucketCount];
            _bucketSizes = new int[BucketCount];

            // Create buckets for power-of-2 sizes
            for (int i = 0; i < BucketCount; i++)
            {
                _buckets[i] = new ConcurrentBag<byte[]>();
                _bucketSizes[i] = 16 << i; // 16, 32, 64, ..., 1048576
            }
        }

        public byte[] Rent(int minimumLength)
        {
            if (minimumLength <= 0)
                throw new ArgumentOutOfRangeException(nameof(minimumLength));

            if (minimumLength > _maxArrayLength)
            {
                return new byte[minimumLength];
            }

            int bucketIndex = SelectBucketIndex(minimumLength);
            if (_buckets[bucketIndex].TryTake(out byte[]? buffer))
            {
                return buffer;
            }

            return new byte[_bucketSizes[bucketIndex]];
        }

        public void Return(byte[] array)
        {
            if (array is null || array.Length > _maxArrayLength)
                return;

            int bucketIndex = SelectBucketIndex(array.Length);
            if (_bucketSizes[bucketIndex] == array.Length)
            {
                Array.Clear(array, 0, array.Length);
                _buckets[bucketIndex].Add(array);
            }
        }

        private int SelectBucketIndex(int bufferSize)
        {
            // Find smallest power-of-2 >= bufferSize
            int index = 0;
            bufferSize--;
            while (bufferSize > 0 && index < BucketCount - 1)
            {
                bufferSize >>= 1;
                index++;
            }
            return Math.Min(index, BucketCount - 1);
        }
    }
}
