---
description: Deep 3-perspective debate for complex TShark/analysis features
---
# UltraThink Protocol

Analyze the requested feature from three conflicting perspectives before coding.

## 1. The Architect (.NET 10 / C# 14)
**Focus**: Process lifecycle, streaming architecture, memory management

**Key Questions**:
- Filter in TShark (Display Filter) or C# (LINQ on Channel<PacketInfo>)?
- Add new field to `-T fields` extraction or derive in StreamingOutputParser?
- Does this fit AnalysisOrchestrator phases (Load/Analyze/Cache)?
- **C# 14 opportunity?** Extension members for builders? `field` keyword? Implicit Span?

**Constraint**: StreamingOutputParser uses Span<T> - no string allocations in hot path.

## 2. The Security Analyst (The User)
**Focus**: Trust, visibility, threat detection workflow

**Key Questions**:
- Can I see/verify the TShark command being executed?
- Does this help me find credentials, anomalies, or threats faster?
- Does the UI make this discoverable? (Dashboard → DrillDown → Details)

**Constraint**: Don't hide raw data - analysts need to trust and verify.

## 3. The Devil's Advocate (The Breaker)
**Focus**: Edge cases, failure modes, security holes

**Key Questions**:
- What if TShark hangs on malformed packets? (timeout handling)
- What if user creates catastrophic display filter? (`TSharkInputValidator`)
- What happens with 10GB+ PCAP? (ParallelTSharkService, memory pressure)

**Constraint**: Handle stderr noise without crashing. Respect CancellationToken.

---

## Output Format

### 1. Debate Summary
| Perspective | Position | Trade-off |
|-------------|----------|-----------|
| Architect | ... | ... |
| Analyst | ... | ... |
| Breaker | ... | ... |

### 2. Architecture Decision
Final design referencing existing patterns:
- Which service owns this? (Core/TShark/UI)
- Integration point? (AnalysisOrchestrator, specific detector, new service)
- C# 14 features to leverage

### 3. Implementation Plan
Numbered checklist following project structure.
