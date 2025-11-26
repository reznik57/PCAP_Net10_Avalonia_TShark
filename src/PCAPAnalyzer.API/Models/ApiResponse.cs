using System.Diagnostics.CodeAnalysis;

namespace PCAPAnalyzer.API.Models;

/// <summary>
/// Standard API response wrapper
/// </summary>
public class ApiResponse<T>
{
    public bool Success { get; set; }
    public T? Data { get; set; }
    public string? Message { get; set; }
    public List<string>? Errors { get; set; }
    public Dictionary<string, string>? Metadata { get; set; }

    [SuppressMessage("Design", "CA1000:Do not declare static members on generic types", Justification = "Factory methods for ApiResponse<T> are intentional design pattern for creating consistent API responses")]
    public static ApiResponse<T> SuccessResult(T data, string? message = null)
    {
        return new ApiResponse<T>
        {
            Success = true,
            Data = data,
            Message = message
        };
    }

    [SuppressMessage("Design", "CA1000:Do not declare static members on generic types", Justification = "Factory methods for ApiResponse<T> are intentional design pattern for creating consistent API responses")]
    public static ApiResponse<T> ErrorResult(string message, List<string>? errors = null)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Errors = errors
        };
    }
}

// NOTE: Custom ProblemDetails class removed.
// Use Microsoft.AspNetCore.Mvc.ProblemDetails for RFC 7807 compliance.
// This provides better integration with ASP.NET Core error handling pipeline.
