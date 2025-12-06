---
description: Generate safe, incremental implementation plan
argument-hint: [Feature Name]
---
# Snowball Execution Plan

Create a safe, incremental plan to implement: **$ARGUMENTS**

## Phase 1: Dependency Verification
- [ ] Does this require new TShark `-e` field? Check `tshark -G fields | grep <field>`
- [ ] New NuGet packages needed? Check .NET 10 compatibility
- [ ] Which layer owns this? (Core services / TShark parsing / UI)

## Phase 2: Locate Integration Points
Reference existing architecture:
- **New packet field?** → `StreamingOutputParser` + `PacketInfo` model
- **New statistic?** → `StatisticsService` or new service in `Core/Services/`
- **New anomaly type?** → Implement `IAnomalyDetector`, register in `UnifiedAnomalyDetectionService`
- **New UI tab section?** → Component ViewModel pattern: `{Tab}{Component}ViewModel`
- **Needs caching?** → Integrate with `SessionAnalysisCache` via `AnalysisOrchestrator`

## Phase 3: C# 14 Opportunities
Identify where to apply modern features:
- **`field` keyword** → Properties with validation/logging in setters
- **`extension` members** → TShark argument builders, Span helpers, filter extensions
- **Implicit Span conversions** → StreamingOutputParser, zero-alloc paths
- **Null-conditional assignment** → `packet?.OptionalField = value;`
- **Lambda modifiers** → `(text, out result) => TryParse(...)` patterns

## Phase 4: Decompose (3-7 increments)
Break into atomic, testable steps:

1. **TShark Verification** - Verify `-T fields -e <field>` output format
2. **Parser Update** - Extend `StreamingOutputParser` if new field needed
3. **Model/Service** - Add to `PacketInfo` or create service in `Core/`
4. **AnalysisOrchestrator** - Wire into analysis phases if needed
5. **ViewModel** - Create/extend using component pattern + `CommunityToolkit.Mvvm`
6. **View** - Avalonia XAML with `{Binding Component.Property}` pattern
7. **Tests** - Mock TShark output in `PCAPAnalyzer.Tests`

## Phase 5: Quality Gates
- [ ] Zero new warnings in `dotnet build`
- [ ] No allocations in `StreamingOutputParser` hot path (use Span<T>)
- [ ] Input validation via `TSharkInputValidator`
- [ ] CancellationToken propagation throughout
- [ ] Works with ParallelTSharkService (thread-safe)

---

## Output
Checklist with:
- Files to create/modify
- C# 14 features to apply
- Estimated complexity (S/M/L)
- Dependencies between steps

Wait for user confirmation before executing.
