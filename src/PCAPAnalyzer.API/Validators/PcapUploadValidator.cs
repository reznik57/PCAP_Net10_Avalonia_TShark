using FluentValidation;
using PCAPAnalyzer.API.DTOs;

namespace PCAPAnalyzer.API.Validators;

public class PcapUploadValidator : AbstractValidator<PcapUploadRequest>
{
    private const long MaxFileSizeBytes = 1024L * 1024L * 1024L; // 1 GB
    private static readonly string[] AllowedExtensions = { ".pcap", ".pcapng", ".cap" };

    public PcapUploadValidator()
    {
        RuleFor(x => x.FileName)
            .NotEmpty().WithMessage("File name is required")
            .Must(BeValidExtension).WithMessage($"File must have one of these extensions: {string.Join(", ", AllowedExtensions)}");

        RuleFor(x => x.FileSize)
            .GreaterThan(0).WithMessage("File size must be greater than 0")
            .LessThanOrEqualTo(MaxFileSizeBytes).WithMessage($"File size must not exceed {MaxFileSizeBytes / (1024 * 1024)} MB");

        RuleFor(x => x.FileData)
            .NotNull().WithMessage("File data is required")
            .NotEmpty().WithMessage("File data cannot be empty");
    }

    private bool BeValidExtension(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
            return false;

        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        return AllowedExtensions.Contains(extension);
    }
}

public class AnalyzeRequestValidator : AbstractValidator<AnalyzeRequest>
{
    private static readonly string[] ValidAnalysisTypes = { "full", "quick", "custom" };

    public AnalyzeRequestValidator()
    {
        When(x => !string.IsNullOrEmpty(x.AnalysisType), () =>
        {
            RuleFor(x => x.AnalysisType)
                .Must(type => ValidAnalysisTypes.Contains(type!.ToLowerInvariant()))
                .WithMessage($"Analysis type must be one of: {string.Join(", ", ValidAnalysisTypes)}");
        });

        When(x => x.Protocols is not null && x.Protocols.Any(), () =>
        {
            RuleFor(x => x.Protocols)
                .Must(protocols => protocols!.All(p => !string.IsNullOrWhiteSpace(p)))
                .WithMessage("Protocol names cannot be empty");
        });
    }
}

public class StartCaptureValidator : AbstractValidator<StartCaptureRequest>
{
    public StartCaptureValidator()
    {
        RuleFor(x => x.InterfaceId)
            .NotEmpty().WithMessage("Interface ID is required");

        When(x => x.MaxPackets.HasValue, () =>
        {
            RuleFor(x => x.MaxPackets!.Value)
                .GreaterThan(0).WithMessage("Max packets must be greater than 0")
                .LessThanOrEqualTo(1000000).WithMessage("Max packets cannot exceed 1,000,000");
        });

        When(x => x.MaxDurationSeconds.HasValue, () =>
        {
            RuleFor(x => x.MaxDurationSeconds!.Value)
                .GreaterThan(0).WithMessage("Max duration must be greater than 0")
                .LessThanOrEqualTo(3600).WithMessage("Max duration cannot exceed 1 hour (3600 seconds)");
        });
    }
}
