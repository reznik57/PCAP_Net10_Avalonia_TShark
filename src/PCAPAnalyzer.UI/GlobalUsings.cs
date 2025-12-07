// Global using directives for PCAPAnalyzer.UI
// Eliminates repetitive using statements across 100+ files

// System namespaces
global using System;
global using System.Collections.Generic;
global using System.Collections.ObjectModel;
global using System.Linq;
global using System.Threading.Tasks;

// MVVM Toolkit
global using CommunityToolkit.Mvvm.ComponentModel;
global using CommunityToolkit.Mvvm.Input;

// Core models and utilities
global using PCAPAnalyzer.Core.Models;
global using PCAPAnalyzer.Core.Extensions;

// UI helpers (excluding Utilities to avoid NumberFormatter ambiguity)
global using PCAPAnalyzer.UI.Helpers;
