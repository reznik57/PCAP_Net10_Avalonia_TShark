// Global code analysis suppressions for PCAPAnalyzer.UI

using System.Diagnostics.CodeAnalysis;

// CA1501: Avoid excessive inheritance - Avalonia framework requirement
// All Avalonia controls inherit from deep framework hierarchies (UserControl -> TemplatedControl -> StyledElement, etc.)
// This is framework-imposed and cannot be avoided
[assembly: SuppressMessage("Design", "CA1501:Avoid excessive inheritance",
    Justification = "Avalonia framework requires deep inheritance hierarchies for UI controls")]

// CA5394: Do not use insecure randomness - Only used for UI visual effects
// Random is used only for animation timing, pulse phases, and visual effects
// Not used for any security-sensitive operations
[assembly: SuppressMessage("Security", "CA5394:Do not use insecure randomness",
    Scope = "member",
    Target = "~M:PCAPAnalyzer.UI.Controls.UnifiedMapControl.#ctor",
    Justification = "Random used only for UI animation timing and visual pulse effects, not for security")]

[assembly: SuppressMessage("Security", "CA5394:Do not use insecure randomness",
    Scope = "member",
    Target = "~M:PCAPAnalyzer.UI.Controls.TrafficFlowRenderer.UpdateFlowPositions",
    Justification = "Random used only for UI traffic flow animation jitter, not for security")]

[assembly: SuppressMessage("Security", "CA5394:Do not use insecure randomness",
    Scope = "member",
    Target = "~M:PCAPAnalyzer.UI.Controls.SimpleWorldMapControl.#ctor",
    Justification = "Random used only for UI marker positioning variations, not for security")]

[assembly: SuppressMessage("Security", "CA5394:Do not use insecure randomness",
    Scope = "type",
    Target = "~T:PCAPAnalyzer.UI.ViewModels.EnhancedMapViewModel",
    Justification = "Random used only for map visualization effects (pulse timing, animation phases), not for security")]

[assembly: SuppressMessage("Security", "CA5394:Do not use insecure randomness",
    Scope = "member",
    Target = "~M:PCAPAnalyzer.UI.Controls.EnhancedWorldMapControl.#ctor",
    Justification = "Random used only for UI animation pulse phase initialization, not for security")]
