using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views
{
    public partial class FilterBar : UserControl
    {
        public FilterBar()
        {
            InitializeComponent();
            AttachToggleHandlers();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
        
        private void AttachToggleHandlers()
        {
            // Attach handlers to toggle buttons after they're loaded
            this.Loaded += (sender, e) =>
            {
                var rfc1918Toggle = this.FindControl<ToggleButton>("RFC1918Toggle");
                var publicIpToggle = this.FindControl<ToggleButton>("PublicIPToggle");
                var multicastToggle = this.FindControl<ToggleButton>("MulticastToggle");
                var broadcastToggle = this.FindControl<ToggleButton>("BroadcastToggle");
                var anycastToggle = this.FindControl<ToggleButton>("AnycastToggle");
                var insecureToggle = this.FindControl<ToggleButton>("InsecureToggle");
                var anomaliesToggle = this.FindControl<ToggleButton>("AnomaliesToggle");
                
                if (rfc1918Toggle != null) rfc1918Toggle.Click += OnPredefinedFilterToggled;
                if (publicIpToggle != null) publicIpToggle.Click += OnPredefinedFilterToggled;
                if (multicastToggle != null) multicastToggle.Click += OnPredefinedFilterToggled;
                if (broadcastToggle != null) broadcastToggle.Click += OnPredefinedFilterToggled;
                if (anycastToggle != null) anycastToggle.Click += OnPredefinedFilterToggled;
                if (insecureToggle != null) insecureToggle.Click += OnPredefinedFilterToggled;
                if (anomaliesToggle != null) anomaliesToggle.Click += OnPredefinedFilterToggled;
            };
        }
        
        private void OnPredefinedFilterToggled(object? sender, RoutedEventArgs e)
        {
            if (sender is not ToggleButton toggleButton) return;
            if (DataContext is not PacketFilterViewModel viewModel) return;
            
            // Determine which filter was toggled based on the toggle button's name
            var filterName = toggleButton.Name?.Replace("Toggle", "", StringComparison.Ordinal) ?? "";
            
            if (toggleButton.IsChecked == true)
            {
                viewModel.AddPredefinedFilterCommand.Execute(filterName);
            }
            else
            {
                viewModel.RemovePredefinedFilterCommand.Execute(filterName);
            }
        }
        
        private void OnAdditionalFilterSelected(object? sender, SelectionChangedEventArgs e)
        {
            if (sender is not ComboBox comboBox) return;
            if (comboBox.SelectedItem is not ComboBoxItem item) return;
            if (DataContext is not PacketFilterViewModel viewModel) return;
            
            var filterTag = item.Tag as string;
            if (string.IsNullOrEmpty(filterTag)) return;
            
            // Apply the selected filter based on the tag
            switch (filterTag)
            {
                case "TcpIssues":
                    viewModel.ApplyTcpIssuesFilterCommand.Execute(null);
                    break;
                case "DnsAnomalies":
                    viewModel.ApplyDnsAnomaliesFilterCommand.Execute(null);
                    break;
                case "PortScan":
                    viewModel.ApplyPortScanFilterCommand.Execute(null);
                    break;
                case "JumboFrames":
                    viewModel.ApplyJumboFramesFilterCommand.Execute(null);
                    break;
                case "Icmp":
                    viewModel.ApplyIcmpFilterCommand.Execute(null);
                    break;
                case "Web":
                    viewModel.ApplyWebTrafficFilterCommand.Execute(null);
                    break;
                case "SecureWeb":
                    viewModel.ApplySecureWebFilterCommand.Execute(null);
                    break;
                case "LinkLocal":
                    viewModel.ApplyLinkLocalFilterCommand.Execute(null);
                    break;
                case "Loopback":
                    viewModel.ApplyLoopbackFilterCommand.Execute(null);
                    break;
                case "Suspicious":
                    viewModel.ApplySuspiciousTrafficFilterCommand.Execute(null);
                    break;
                case "PrivateToPublic":
                    viewModel.ApplyPrivateToPublicFilterCommand.Execute(null);
                    break;
                case "PublicToPrivate":
                    viewModel.ApplyPublicToPrivateFilterCommand.Execute(null);
                    break;
            }
            
            // Reset the combo box selection after applying filter
            comboBox.SelectedIndex = -1;
        }
    }
}