using FluentAssertions;
using FluentAssertions.Execution;
using PCAPAnalyzer.Core.Collections;
using Xunit;

namespace PCAPAnalyzer.Tests.Services;

/// <summary>
/// Comprehensive tests for CircularBuffer implementation.
/// Tests capacity management, thread safety, and edge cases.
/// </summary>
public class CircularBufferTests
{
    [Fact]
    public void Constructor_WithValidCapacity_ShouldInitialize()
    {
        // Arrange & Act
        var buffer = new CircularBuffer<int>(10);

        // Assert
        using var scope = new AssertionScope();
        buffer.Capacity.Should().Be(10);
        buffer.Count.Should().Be(0);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Constructor_WithInvalidCapacity_ShouldThrow(int capacity)
    {
        // Act
        var act = () => new CircularBuffer<int>(capacity);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Add_WhenNotFull_ShouldAddItem()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);

        // Act
        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(3);
    }

    [Fact]
    public void Add_WhenFull_ShouldOverwriteOldest()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(3);
        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);

        // Act
        buffer.Add(4);
        buffer.Add(5);

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(3);
        buffer.ToArray().Should().Equal(3, 4, 5);
    }

    [Fact]
    public void GetItem_WithValidIndex_ShouldReturnItem()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);
        buffer.Add(10);
        buffer.Add(20);
        buffer.Add(30);

        // Act
        var items = buffer.ToArray();

        // Assert
        using var scope = new AssertionScope();
        items.Length.Should().Be(3);
        items[1].Should().Be(20);
    }

    [Fact]
    public void Clear_ShouldRemoveAllItems()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);
        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);

        // Act
        buffer.Clear();

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(0);
    }

    [Fact]
    public void ToArray_ShouldReturnItemsInOrder()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);
        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);

        // Act
        var array = buffer.ToArray();

        // Assert
        array.Should().Equal(1, 2, 3);
    }

    [Fact]
    public void ToArray_AfterWraparound_ShouldReturnCorrectOrder()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(3);
        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);
        buffer.Add(4);
        buffer.Add(5);

        // Act
        var array = buffer.ToArray();

        // Assert
        array.Should().Equal(3, 4, 5);
    }

    [Fact]
    public void Enumeration_ShouldIterateInOrder()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);
        buffer.Add(10);
        buffer.Add(20);
        buffer.Add(30);

        // Act
        var items = buffer.ToList();

        // Assert
        items.Should().Equal(10, 20, 30);
    }

    [Fact]
    public void Enumeration_AfterWraparound_ShouldIterateCorrectly()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(3);
        for (int i = 1; i <= 7; i++)
        {
            buffer.Add(i);
        }

        // Act
        var items = buffer.ToList();

        // Assert
        items.Should().Equal(5, 6, 7);
    }

    [Fact]
    public void ConcurrentAdd_ShouldBeThreadSafe()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(1000);
        var tasks = new List<Task>();

        // Act
        for (int i = 0; i < 10; i++)
        {
            var threadId = i;
            tasks.Add(Task.Run(() =>
            {
                for (int j = 0; j < 100; j++)
                {
                    buffer.Add(threadId * 100 + j);
                }
            }));
        }

        Task.WaitAll(tasks.ToArray());

        // Assert
        buffer.Count.Should().Be(1000);
    }

    [Fact]
    public void ConcurrentReadWrite_ShouldBeThreadSafe()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(100);
        var exceptions = new List<Exception>();
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        // Act
        var writerTask = Task.Run(async () =>
        {
            try
            {
                int value = 0;
                while (!cts.Token.IsCancellationRequested)
                {
                    buffer.Add(value++);
                    await Task.Delay(1, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                lock (exceptions) exceptions.Add(ex);
            }
        });

        var readerTask = Task.Run(async () =>
        {
            try
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    _ = buffer.ToArray();
                    await Task.Delay(1, cts.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                lock (exceptions) exceptions.Add(ex);
            }
        });

        Task.WaitAll(writerTask, readerTask);

        // Assert
        exceptions.Should().BeEmpty();
    }

    [Fact]
    public void AddRange_ShouldAddMultipleItems()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(10);
        var items = new[] { 1, 2, 3, 4, 5 };

        // Act
        foreach (var item in items)
        {
            buffer.Add(item);
        }

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(5);
        buffer.ToArray().Should().Equal(items);
    }

    [Fact]
    public void AddRange_ExceedingCapacity_ShouldOverwrite()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(3);
        var items = new[] { 1, 2, 3, 4, 5 };

        // Act
        foreach (var item in items)
        {
            buffer.Add(item);
        }

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(3);
        buffer.ToArray().Should().Equal(3, 4, 5);
    }

    [Fact]
    public void LargeCapacity_ShouldHandleEfficiently()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(10000);

        // Act
        for (int i = 0; i < 10000; i++)
        {
            buffer.Add(i);
        }

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(10000);
        buffer.ToArray()[0].Should().Be(0);
        buffer.ToArray()[9999].Should().Be(9999);
    }

    [Fact]
    public void Contains_ShouldFindExistingItem()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);
        buffer.Add(10);
        buffer.Add(20);
        buffer.Add(30);

        // Act
        var contains20 = buffer.Contains(20);
        var contains40 = buffer.Contains(40);

        // Assert
        using var scope = new AssertionScope();
        contains20.Should().BeTrue();
        contains40.Should().BeFalse();
    }

    [Fact]
    public void IndexOf_ShouldReturnCorrectIndex()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);
        buffer.Add(10);
        buffer.Add(20);
        buffer.Add(30);

        // Act
        var items = buffer.ToArray();
        var index = Array.IndexOf(items, 20);
        var notFound = Array.IndexOf(items, 40);

        // Assert
        using var scope = new AssertionScope();
        index.Should().Be(1);
        notFound.Should().Be(-1);
    }

    [Fact]
    public void Capacity_ShouldRemainConstant()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);

        // Act
        for (int i = 0; i < 100; i++)
        {
            buffer.Add(i);
        }

        // Assert
        buffer.Capacity.Should().Be(5);
    }

    [Fact]
    public void ReferenceTypes_ShouldHandleNulls()
    {
        // Arrange
        var buffer = new CircularBuffer<string?>(5);

        // Act
        buffer.Add("test");
        buffer.Add(null);
        buffer.Add("hello");

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(3);
        buffer.ToArray()[1].Should().BeNull();
    }

    [Fact]
    public void ComplexTypes_ShouldMaintainReferences()
    {
        // Arrange
        var buffer = new CircularBuffer<List<int>>(3);
        var list1 = new List<int> { 1, 2, 3 };
        var list2 = new List<int> { 4, 5, 6 };

        // Act
        buffer.Add(list1);
        buffer.Add(list2);

        // Assert
        using var scope = new AssertionScope();
        buffer.ToArray()[0].Should().BeSameAs(list1);
        buffer.ToArray()[1].Should().BeSameAs(list2);
    }

    [Fact]
    public void EdgeCase_SingleCapacity_ShouldWork()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(1);

        // Act
        buffer.Add(1);
        buffer.Add(2);
        buffer.Add(3);

        // Assert
        using var scope = new AssertionScope();
        buffer.Count.Should().Be(1);
        buffer.ToArray()[0].Should().Be(3);
    }

    [Fact]
    public void EdgeCase_ZeroCount_Operations_ShouldHandleGracefully()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(5);

        // Act & Assert
        using var scope = new AssertionScope();
        buffer.ToArray().Should().BeEmpty();
        buffer.Contains(1).Should().BeFalse();
        Array.IndexOf(buffer.ToArray(), 1).Should().Be(-1);
    }

    [Fact]
    public void Performance_ManyOperations_ShouldCompleteQuickly()
    {
        // Arrange
        var buffer = new CircularBuffer<int>(1000);
        var sw = System.Diagnostics.Stopwatch.StartNew();

        // Act
        for (int i = 0; i < 100000; i++)
        {
            buffer.Add(i);
        }
        sw.Stop();

        // Assert
        sw.ElapsedMilliseconds.Should().BeLessThan(1000, "100k operations should complete under 1 second");
    }
}
