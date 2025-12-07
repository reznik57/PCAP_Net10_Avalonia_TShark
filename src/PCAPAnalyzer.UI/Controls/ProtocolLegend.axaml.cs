using System.Collections.Generic;
using System.Linq;
using Avalonia.Controls;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.Controls;

/// <summary>
/// A control that displays a legend of protocol colors.
/// Can show common protocols only or all available protocols.
/// </summary>
public partial class ProtocolLegend : UserControl
{
    private readonly IProtocolColorService _colorService;

    public ProtocolLegend()
    {
        InitializeComponent();

        // Use DI container, fallback to direct instantiation only if DI not available
        _colorService = App.Services?.GetService<IProtocolColorService>() ?? new ProtocolColorService();

        LoadProtocols();
    }

    private void LoadProtocols()
    {
        // Load common protocols
        var commonProtocols = _colorService.GetCommonProtocolColors();
        var commonItems = commonProtocols.Select(kvp => new ProtocolLegendItem
        {
            Protocol = kvp.Key,
            Description = kvp.Value.Description
        }).ToList();

        var commonList = this.FindControl<ItemsControl>("CommonProtocolsList");
        if (commonList is not null)
        {
            commonList.ItemsSource = commonItems;
        }

        // Load all protocols
        var allProtocols = _colorService.GetAllProtocolColors();
        var allItems = allProtocols
            .Where(kvp => !commonProtocols.ContainsKey(kvp.Key)) // Exclude common protocols
            .Select(kvp => new ProtocolLegendItem
            {
                Protocol = kvp.Key,
                Description = kvp.Value.Description
            })
            .OrderBy(p => p.Protocol)
            .ToList();

        var allList = this.FindControl<ItemsControl>("AllProtocolsList");
        if (allList is not null)
        {
            allList.ItemsSource = allItems;
        }

        // Load category view
        LoadCategoryView();

        // Update footer
        UpdateFooter(commonProtocols.Count, allProtocols.Count);
    }

    private void LoadCategoryView()
    {
        var allProtocols = _colorService.GetAllProtocolColors();

        // Group by category
        var categories = allProtocols
            .GroupBy(kvp => _colorService.GetProtocolCategory(kvp.Key))
            .OrderBy(g => g.Key)
            .Select(g => new ProtocolCategoryGroup
            {
                Category = g.Key,
                Protocols = g.Select(p => p.Key).OrderBy(p => p).ToList()
            })
            .ToList();

        var categoryList = this.FindControl<ItemsControl>("CategoryList");
        if (categoryList is not null)
        {
            categoryList.ItemsSource = categories;
        }
    }

    private void UpdateFooter(int commonCount, int totalCount)
    {
        var footer = this.FindControl<TextBlock>("FooterText");
        if (footer is not null)
        {
            footer.Text = $"{commonCount} common protocols • {totalCount} total protocols supported";
        }
    }

    // Property to control display mode
    private bool _showCommonOnly = true;
    public bool ShowCommonOnly
    {
        get => _showCommonOnly;
        set
        {
            _showCommonOnly = value;
            var allPanel = this.FindControl<StackPanel>("AllProtocolsPanel");
            var categoryPanel = this.FindControl<StackPanel>("CategoryPanel");

            if (allPanel is not null)
                allPanel.IsVisible = !value && !ShowByCategory;

            if (categoryPanel is not null)
                categoryPanel.IsVisible = !value && ShowByCategory;
        }
    }

    private bool _showByCategory;
    public bool ShowByCategory
    {
        get => _showByCategory;
        set
        {
            _showByCategory = value;
            var allPanel = this.FindControl<StackPanel>("AllProtocolsPanel");
            var categoryPanel = this.FindControl<StackPanel>("CategoryPanel");

            if (allPanel is not null)
                allPanel.IsVisible = !ShowCommonOnly && !value;

            if (categoryPanel is not null)
                categoryPanel.IsVisible = !ShowCommonOnly && value;
        }
    }
}

/// <summary>
/// Data model for protocol legend items.
/// </summary>
public class ProtocolLegendItem
{
    public string Protocol { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// Data model for protocol category groups.
/// </summary>
public class ProtocolCategoryGroup
{
    public string Category { get; set; } = string.Empty;
    public List<string> Protocols { get; set; } = [];
}
