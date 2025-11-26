using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Helpers
{
    /// <summary>
    /// Manages command state during updates to prevent threading issues
    /// </summary>
    public static class CommandManager
    {
        private static readonly HashSet<IRelayCommand> _commands = new();
        private static bool _globalEnabled = true;
        
        /// <summary>
        /// Register a command for management
        /// </summary>
        public static void RegisterCommand(IRelayCommand command)
        {
            lock (_commands)
            {
                _commands.Add(command);
            }
        }
        
        /// <summary>
        /// Temporarily disable all commands during updates
        /// </summary>
        public static IDisposable DisableCommands()
        {
            SetCommandsEnabled(false);
            return new CommandEnabler();
        }
        
        private static void SetCommandsEnabled(bool enabled)
        {
            _globalEnabled = enabled;
            lock (_commands)
            {
                foreach (var command in _commands)
                {
                    command.NotifyCanExecuteChanged();
                }
            }
        }
        
        private class CommandEnabler : IDisposable
        {
            public void Dispose()
            {
                SetCommandsEnabled(true);
            }
        }
        
        public static bool AreCommandsEnabled => _globalEnabled;
    }
}