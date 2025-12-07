using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using PCAPAnalyzer.UI.ViewModels; // For FlowRecordViewModel

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class FlowSummaryViewModel : ObservableObject
{
    public ObservableCollection<FlowRecordViewModel> Flows { get; } = [];

    [ObservableProperty]
    private int _totalFlows;

    public IRelayCommand ExportCsvCommand { get; }
    public IRelayCommand ExportPdfCommand { get; }

    public FlowSummaryViewModel()
    {
        ExportCsvCommand = new AsyncRelayCommand(ExportCsvAsync);
        ExportPdfCommand = new AsyncRelayCommand(ExportPdfAsync);
    }

    public void LoadFlows(IEnumerable<FlowRecord> flows)
    {
        Flows.Clear();
        foreach (var flow in flows.OrderByDescending(f => f.ByteCount))
        {
            Flows.Add(FlowRecordViewModel.FromRecord(flow));
        }
        TotalFlows = Flows.Count;
    }

    private Task ExportCsvAsync()
    {
        var path = Path.Combine(Environment.CurrentDirectory, "analysis", "exports", $"flows_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var sb = new StringBuilder();
        sb.AppendLine("SourceIP,SourcePort,DestinationIP,DestinationPort,Protocol,Packets,Bytes,FirstSeen,LastSeen");
        foreach (var flow in Flows)
        {
            sb.AppendLine($"{flow.SourceIP},{flow.SourcePort},{flow.DestinationIP},{flow.DestinationPort},{flow.Protocol},{flow.PacketCount},{flow.ByteCount},{flow.FirstSeen:O},{flow.LastSeen:O}");
        }
        File.WriteAllText(path, sb.ToString());
        return Task.CompletedTask;
    }

    private Task ExportPdfAsync()
    {
        var path = Path.Combine(Environment.CurrentDirectory, "analysis", "exports", $"flows_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var document = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Margin(40);
                page.Header().Text("Flow Summary").Bold().FontSize(20);
                page.Content().Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.RelativeColumn(2);
                        columns.RelativeColumn(1);
                        columns.RelativeColumn(2);
                        columns.RelativeColumn(1);
                        columns.RelativeColumn(1);
                        columns.RelativeColumn(1);
                        columns.RelativeColumn(1);
                    });

                    table.Header(header =>
                    {
                        header.Cell().Text("Source").Bold();
                        header.Cell().Text("SrcPort").Bold();
                        header.Cell().Text("Destination").Bold();
                        header.Cell().Text("DstPort").Bold();
                        header.Cell().Text("Proto").Bold();
                        header.Cell().Text("Packets").Bold();
                        header.Cell().Text("Bytes").Bold();
                    });

                    foreach (var flow in Flows)
                    {
                        table.Cell().Text(flow.SourceIP);
                        table.Cell().Text(flow.SourcePort.ToString());
                        table.Cell().Text(flow.DestinationIP);
                        table.Cell().Text(flow.DestinationPort.ToString());
                        table.Cell().Text(flow.Protocol);
                        table.Cell().Text(flow.PacketCount.ToString());
                        table.Cell().Text(flow.ByteCount.ToString());
                    }
                });
            });
        });

        document.GeneratePdf(path);
        return Task.CompletedTask;
    }
}
