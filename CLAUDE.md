# Claude Code Configuration - PCAP Analyzer Project

## Communication Style

Be extremely concise. Sacrifice grammar for concision in all interactions and commit messages.

## Plans & Decision Making

### Plan Mode Usage
- **MUST use Plan Mode (`/plan`)** for major changes:
  - New features, major refactors, architecture changes
  - Multi-file modifications, large code restructures
  - Complex debugging requiring exploration

### Clarification Before Action
- **ALWAYS ask user if unclear** (minor OR major changes)
- **Provide options** - let user choose approach
- **Be concise** - sacrifice grammar for clarity
- End plans with unresolved questions (extremely concise)

### Examples
**Major change:** "Add real-time capture feature"
→ **Use Plan Mode** first, present options, ask unclear points

**Minor change:** "Fix null reference bug in TSharkService"
→ If approach unclear, **ask first**: "Fix via null check or optional pattern?"

---

## 🚨 CRITICAL: CONCURRENT EXECUTION & FILE MANAGEMENT

### ABSOLUTE RULES

1. **ALL operations MUST be concurrent/parallel in single message**
2. **NEVER save working files, text/mds, tests to root folder**
3. **ALWAYS organize files in appropriate subdirectories**

### ⚡ GOLDEN RULE: "1 MESSAGE = ALL RELATED OPERATIONS"

**MANDATORY PATTERNS:**
- **TodoWrite**: Batch ALL todos in ONE call (5-10+ minimum)
- **Task tool**: Spawn ALL agents in ONE message with full instructions
- **File operations**: Batch ALL reads/writes/edits in ONE message
- **Bash commands**: Batch ALL terminal operations in ONE message

### 📁 File Organization Rules

**NEVER save to root. Use these directories:**
- `/src` - Source code
- `/tests` - Test files
- `/docs` - Documentation, markdown files
- `/config` - Configuration files
- `/scripts` - Utility scripts
- `/examples` - Example code

---

## Project Overview

Enterprise PCAP network packet analyzer built with:
- **.NET 9.0** (C#)
- **Avalonia UI** (cross-platform desktop)
- **TShark** (packet analysis engine)
- **LiveCharts2** (visualization)

### Architecture
- **PCAPAnalyzer.Core** - Business logic, services, analysis
- **PCAPAnalyzer.TShark** - TShark integration, command building
- **PCAPAnalyzer.UI** - Avalonia MVVM views/viewmodels
- **PCAPAnalyzer.API** - REST API (optional)
- **PCAPAnalyzer.Tests** - xUnit test suite

---

## Build Commands

```bash
# Build solution
dotnet build

# Run tests
dotnet test

# Run application
dotnet run --project src/PCAPAnalyzer.UI

# Clean build artifacts
dotnet clean

# Restore packages
dotnet restore

# Publish for deployment
dotnet publish -c Release
```

---

## Code Style & Best Practices

### General
- **Modular Design**: Files under 500 lines
- **Environment Safety**: Never hardcode secrets
- **Test-First**: Write tests before implementation
- **Clean Architecture**: Separate concerns
- **Documentation**: Keep inline docs updated
- **Async/Await**: Use proper async patterns
- **Error Handling**: Comprehensive try-catch with logging

### C# Specific
- Use **nullable reference types**
- Follow **Microsoft C# coding conventions**
- Use **MVVM pattern** for UI (Avalonia)
- Prefer **dependency injection**
- Use **CancellationToken** for long operations
- **IDisposable** pattern for resources
- **ConfigureAwait(false)** in library code

### Enterprise Requirements
- **Security**: Input validation, sanitization
- **Performance**: Memory profiling, optimization
- **Logging**: Structured logging (Serilog pattern)
- **Configuration**: appsettings.json, environment vars
- **Error Recovery**: Graceful degradation

---

## Project-Specific Guidelines

### PCAP Analysis
- Stream large files (don't load entire PCAP into memory)
- Use TShark efficiently (minimize spawned processes)
- Implement progress reporting for long operations
- Cache frequently accessed packet data

### UI Development
- Keep ViewModels testable (no UI dependencies)
- Use ReactiveUI patterns for data binding
- Implement proper INotifyPropertyChanged
- Virtualize large lists/grids
- Background threads for heavy operations

### Security
- Validate TShark command inputs (prevent injection)
- Sanitize file paths (prevent directory traversal)
- Handle sensitive network data appropriately
- Implement audit logging for security events

---

## Agent Usage Guidelines - Token Efficiency

**Use agents ONLY for specialized, complex tasks:**

### ✅ Use Agents When:
- **Architecture reviews** - Multi-file refactoring, design patterns, MVVM optimization
- **Complete UI transformations** - Full view redesigns, Dashboard-style implementations
- **Security audits** - Comprehensive vulnerability assessment, enterprise compliance
- **Performance optimization** - Memory profiling, PCAP processing bottlenecks
- **Complex analysis** - 3+ file exploration, pattern discovery, system-wide changes

### ❌ Do NOT Use Agents For:
- Single file edits (use Edit tool directly)
- Simple bug fixes or null checks
- Adding comments or documentation
- Straightforward XAML/C# changes
- Quick searches or file reads
- Build/test commands

### 📊 Token Cost Awareness:
Agents consume **80-120k tokens** per invocation due to:
- Independent file reads (no shared context)
- Complete analysis and deliverables
- System overhead and tool execution

**Balance:** Quality specialized work vs. token efficiency

### Available Specialized Agents

**Architecture & Performance:**
- `pcap-architecture-optimizer` - Multi-file architecture review, MVVM patterns
- `pcap-performance-optimizer` - Memory/CPU profiling, large file optimization
- `pcap-tshark-optimizer` - TShark process management, command optimization

**UI Development:**
- `avalonia-ui-architect` - Complete view transformations, Dashboard harmonization

**Quality & Security:**
- `csharp-quality-guardian` - Code review, test strategy, best practices
- `enterprise-security-auditor` - Security vulnerability assessment
- `enterprise-deployment-specialist` - Production deployment, enterprise integration

**Domain-Specific:**
- VoIP, DNS, intrusion detection agents (use sparingly, only when needed)

---

## Concurrent Execution Examples

### ✅ CORRECT (Single Message):

```csharp
// Read multiple files in parallel
Read("src/PCAPAnalyzer.Core/Services/TSharkService.cs")
Read("src/PCAPAnalyzer.UI/ViewModels/MainWindowViewModel.cs")
Read("tests/PCAPAnalyzer.Tests/TSharkServiceTests.cs")

// Batch todos
TodoWrite({
  todos: [
    {content: "Review TShark service", status: "in_progress", activeForm: "Reviewing TShark service"},
    {content: "Update ViewModel", status: "pending", activeForm: "Updating ViewModel"},
    {content: "Add unit tests", status: "pending", activeForm: "Adding unit tests"},
    {content: "Run build", status: "pending", activeForm: "Running build"},
    {content: "Fix warnings", status: "pending", activeForm: "Fixing warnings"}
  ]
})

// Execute related bash commands together
Bash("dotnet build && dotnet test")
```

### ❌ WRONG (Multiple Messages):

```csharp
Message 1: Read("file1.cs")
Message 2: Read("file2.cs")
Message 3: TodoWrite with single todo
Message 4: Bash("dotnet build")
// Inefficient! Batch all operations in single message
```

---

## Important Reminders

- Do what has been asked; nothing more, nothing less
- NEVER create files unless absolutely necessary
- ALWAYS prefer editing existing files to creating new ones
- NEVER proactively create documentation files (*.md) or READMEs unless explicitly requested
- Never save working files, text/mds, tests to root folder
- **Use agents judiciously** - only for complex specialized tasks (see Agent Guidelines above)
- Always fix all warnings and errors during dotnet build
- Prefer direct tool use (Read, Edit, Grep) over agents for simple tasks
- I dont want any warnings or errors during dotnet build. also check this after every task (keep in mind you are in wsl i am using windows 11)