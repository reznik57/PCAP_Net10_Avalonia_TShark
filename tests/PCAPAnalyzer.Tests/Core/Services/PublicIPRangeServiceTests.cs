using System;
using System.Threading.Tasks;
using FluentAssertions;
using PCAPAnalyzer.Core.Services;
using Xunit;

namespace PCAPAnalyzer.Tests.Core.Services
{
    /// <summary>
    /// Tests for PublicIPRangeService IDisposable implementation
    /// Ensures proper resource management and disposal behavior
    /// </summary>
    public class PublicIPRangeServiceTests
    {
        [Fact]
        public void Dispose_MultipleCalls_DoesNotThrow()
        {
            // Arrange
            var service = new PublicIPRangeService();

            // Act
            service.Dispose();
            var action = () => service.Dispose();

            // Assert
            action.Should().NotThrow("multiple Dispose calls should be safe (idempotent)");
        }

        [Fact]
        public async Task InitializeAsync_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var service = new PublicIPRangeService();
            service.Dispose();

            // Act
            Func<Task> action = async () => await service.InitializeAsync();

            // Assert
            await action.Should().ThrowAsync<ObjectDisposedException>()
                .WithMessage("*PublicIPRangeService*");
        }

        [Fact]
        public async Task GetCountryCodeAsync_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var service = new PublicIPRangeService();
            service.Dispose();

            // Act
            Func<Task> action = async () => await service.GetCountryCodeAsync("8.8.8.8");

            // Assert
            await action.Should().ThrowAsync<ObjectDisposedException>()
                .WithMessage("*PublicIPRangeService*");
        }

        [Fact]
        public async Task GetLocationAsync_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var service = new PublicIPRangeService();
            service.Dispose();

            // Act
            Func<Task> action = async () => await service.GetLocationAsync("8.8.8.8");

            // Assert
            await action.Should().ThrowAsync<ObjectDisposedException>()
                .WithMessage("*PublicIPRangeService*");
        }

        [Fact]
        public async Task UpdateDatabaseAsync_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var service = new PublicIPRangeService();
            service.Dispose();

            // Act
            Func<Task> action = async () => await service.UpdateDatabaseAsync();

            // Assert
            await action.Should().ThrowAsync<ObjectDisposedException>()
                .WithMessage("*PublicIPRangeService*");
        }

        [Fact]
        public async Task GetTotalRangesCount_AfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var service = new PublicIPRangeService();
            service.Dispose();

            // Act
            Func<Task> action = async () => await service.GetTotalRangesCount();

            // Assert
            await action.Should().ThrowAsync<ObjectDisposedException>()
                .WithMessage("*PublicIPRangeService*");
        }

        [Fact]
        public void Dispose_DisposesHttpClient()
        {
            // Arrange
            var service = new PublicIPRangeService();

            // Act
            service.Dispose();

            // Assert
            // HttpClient is disposed, subsequent calls should throw ObjectDisposedException
            Func<Task> action = async () => await service.GetCountryCodeAsync("8.8.8.8");
            action.Should().ThrowAsync<ObjectDisposedException>();
        }

        [Fact]
        public void IsInitialized_AfterDispose_CanStillBeRead()
        {
            // Arrange
            var service = new PublicIPRangeService();
            var initialValue = service.IsInitialized;

            // Act
            service.Dispose();
            var action = () => service.IsInitialized;

            // Assert
            action.Should().NotThrow("reading property after dispose should not throw");
            service.IsInitialized.Should().Be(initialValue, "property value should remain accessible");
        }

        [Fact]
        public async Task Dispose_BeforeInitialization_DisposesCleanly()
        {
            // Arrange
            var service = new PublicIPRangeService();

            // Act - Dispose without ever initializing
            var action = () => service.Dispose();

            // Assert
            action.Should().NotThrow("disposing before initialization should be safe");
            service.IsInitialized.Should().BeFalse();
        }

        [Fact]
        public async Task UsingStatement_AutomaticallyDisposesService()
        {
            // Arrange & Act
            PublicIPRangeService service;
            using (service = new PublicIPRangeService())
            {
                // Service is active within using block
                service.IsInitialized.Should().BeFalse();
            }

            // Assert - Service should be disposed after using block
            Func<Task> action = async () => await service.GetCountryCodeAsync("8.8.8.8");
            await action.Should().ThrowAsync<ObjectDisposedException>();
        }
    }
}
