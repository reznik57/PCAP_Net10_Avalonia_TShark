---
description: Deep 3-perspective debate for complex TShark/analysis features
---
# UltraThink Protocol v2

**Auto-trigger on**: Multi-file changes, new services/detectors, architecture decisions, TShark integration, performance-critical paths.
**Skip for**: Single-file edits, typo fixes, simple config changes.

---

## Phase 0: Clarification Gate

Before deep analysis, identify 1-2 critical unknowns. Ask the user using `AskUserQuestion`:

**Ask if unclear:**
- Scope: Full implementation or proof-of-concept?
- Trade-off: Prioritize speed, memory, or maintainability?
- Integration: Which existing service/phase should own this?
- C# 14: Any specific modern features they want demonstrated?

**Skip clarification if**: Requirements are unambiguous from context.

---

## Phase 1: Critical Rejection Check

**STOP IMMEDIATELY** and challenge the user if you detect:
- Shell injection vectors (unsanitized input to TShark)
- Buffering full PCAP/stdout (violates streaming-only rule)
- String allocations in hot paths (StreamingOutputParser)
- Breaking change to `-T fields` output format
- Coupling UI directly to TShark process

**For minor concerns**: Flag in debate summary, don't stop.

---

## Phase 2: Three-Perspective Debate

### The Architect (.NET 10 / C# 14)
**Focus**: Process lifecycle, streaming architecture, memory management

| Question | Why It Matters |
|----------|----------------|
| Filter in TShark or C# LINQ? | TShark = less data transferred; LINQ = more flexible |
| New `-e` field or derive in parser? | New field = TShark handles edge cases; derive = no TShark change |
| Fits AnalysisOrchestrator phases? | Load (2-50%) / Analyze (50-92%) / Cache (92-100%) |
| C# 14 opportunity? | `field` keyword, `extension` members, implicit Span |

**Constraint**: StreamingOutputParser uses Span<T> - zero allocations in hot path.

### The Security Analyst (The User)
**Focus**: Trust, visibility, threat detection workflow

| Question | Why It Matters |
|----------|----------------|
| Can I verify the TShark command? | Analysts need to trust what's being executed |
| Does this find threats faster? | Credentials, anomalies, exfiltration detection |
| Is it discoverable? | Dashboard → DrillDown → Details flow |
| Raw data accessible? | Don't hide data - analysts verify |

**Constraint**: Never obscure the underlying TShark behavior.

### The Devil's Advocate (The Breaker)
**Focus**: Edge cases, failure modes, security holes

| Question | Why It Matters |
|----------|----------------|
| TShark hangs on malformed packets? | Need timeout + CancellationToken |
| Catastrophic display filter? | TSharkInputValidator must catch |
| 10GB+ PCAP handling? | ParallelTSharkService, memory pressure |
| Thread-safety? | ParallelTSharkService uses concurrent execution |

**Constraint**: Handle stderr noise gracefully. Respect CancellationToken everywhere.

---

## Phase 3: Debate Output

### Summary Table
| Perspective | Position | Trade-off | Concerns |
|-------------|----------|-----------|----------|
| Architect | ... | ... | Minor flags |
| Analyst | ... | ... | ... |
| Breaker | ... | ... | Critical if any |

### Architecture Decision
- **Owner**: Which service/layer? (Core/TShark/UI)
- **Integration**: AnalysisOrchestrator phase or standalone?
- **C# 14 Features**: Specific opportunities identified

### Recommendation
Primary path with clear justification. Include alternatives if trade-offs are close.

---

## ⏸️ CHECKPOINT: User Confirmation

**Ask**: "Proceed with implementation plan? Or adjust the approach?"

Wait for user confirmation before Phase 4.

---

## Phase 4: Snowball Implementation Plan

*Only after user confirms Phase 3.*

### 4.1 Dependency Verification
- [ ] New TShark `-e` field needed? (`tshark -G fields | grep <field>`)
- [ ] New NuGet packages? Check .NET 10 compatibility
- [ ] Layer ownership confirmed? (Core/TShark/UI)

### 4.2 Integration Points
| Change Type | Target Location |
|-------------|-----------------|
| New packet field | `StreamingOutputParser` + `PacketInfo` model |
| New statistic | `StatisticsService` or new service in `Core/Services/` |
| New anomaly | Implement `IAnomalyDetector`, register in `UnifiedAnomalyDetectionService` |
| New UI section | Component pattern: `{Tab}{Component}ViewModel` |
| Needs caching | `SessionAnalysisCache` via `AnalysisOrchestrator` |

### 4.3 Incremental Steps (3-7 atomic changes)
Each step must be independently testable:

1. **TShark Verification** - Verify `-T fields -e <field>` output
2. **Parser Update** - Extend StreamingOutputParser (Span<T>!)
3. **Model/Service** - Add to PacketInfo or create service
4. **Orchestrator** - Wire into analysis phases if needed
5. **ViewModel** - Component pattern + CommunityToolkit.Mvvm
6. **View** - Avalonia XAML with `{Binding Component.Property}`
7. **Tests** - Mock TShark output in PCAPAnalyzer.Tests

### 4.4 C# 14 Application Checklist
- [ ] `field` keyword → Properties with validation/notification
- [ ] `extension` members → TShark builders, Span helpers
- [ ] Implicit Span → StreamingOutputParser, zero-alloc
- [ ] Null-conditional assignment → Optional packet fields
- [ ] Lambda modifiers → TryParse patterns

---

## Phase 5: Quality Gates

Before marking complete:
- [ ] `dotnet build` - Zero warnings
- [ ] No allocations in hot paths (StreamingOutputParser)
- [ ] `TSharkInputValidator` covers new inputs
- [ ] CancellationToken propagated throughout
- [ ] Thread-safe for ParallelTSharkService
- [ ] UI responsive during large file analysis

---

## Post-Mortem (After Implementation)

Answer these three questions:

| Check | Question | Pass Criteria |
|-------|----------|---------------|
| **Works?** | Does it function as designed? | Tests pass, no runtime errors |
| **Good?** | Code quality acceptable? | Zero warnings, no allocations in hot path, thread-safe |
| **UX?** | User experience solid? | Discoverable, trustworthy, efficient workflow |

---

## Quick Reference

**Perspectives**: Architect (perf/memory) → Analyst (utility/trust) → Breaker (edge cases)

**Flow**: Clarify → Reject Critical → Debate → Confirm → Plan → Gates → Post-Mortem

**Stop for**: Injection, buffering, hot-path strings, `-T fields` breaks, UI-TShark coupling

**Flag for**: Minor perf concerns, non-critical style issues, future refactor opportunities
