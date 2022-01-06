using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Commands
{
    public class RelayCommand<T> : ICommand
    {
        private readonly Predicate<T?>? _canExecute;
        private readonly Action<T?> _execute;

        public RelayCommand(Action<T?> execute) : this(execute, null)
        {
            _execute = execute;
        }

        public RelayCommand(Action<T?>? execute, Predicate<T?>? canExecute)
        {
            if (execute is null)
            {
                throw new ArgumentException(null, nameof(execute));
            }
            _execute = execute;
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter)
        {
            return _canExecute == null || _canExecute((T?)parameter);
        }

        public void Execute(object? parameter)
        {
            _execute((T?)parameter);
        }

        public event EventHandler? CanExecuteChanged
        {
            add
            {
                CommandManager.RequerySuggested += value;
            }
            remove
            {
                CommandManager.RequerySuggested -= value;
            }
        }
    }

    public class RelayCommand : ICommand
    {
        private readonly Predicate<object?>? _canExecute;
        private readonly Action<object?> _execute;
        private event EventHandler? CanExecuteChangedInternal;

        public RelayCommand(Action<object?> execute) : this(execute, null)
        {
            _execute = execute;
        }

        public RelayCommand(Action<object?> execute, Predicate<object?>? canExecute)
        {
            if (execute is null)
            {
                throw new ArgumentException(null, nameof(execute));
            }
            _execute = execute;
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter)
        {
            return _canExecute == null || _canExecute(parameter);
        }

        public void Execute(object? parameter)
        {
            _execute(parameter);
        }

        public event EventHandler? CanExecuteChanged
        {
            add
            {
                CommandManager.RequerySuggested += value;
                CanExecuteChangedInternal += value;
            }
            remove
            {
                CommandManager.RequerySuggested -= value;
                CanExecuteChangedInternal -= value;
            }
        }

        public void RaiseCanExecuteChanged()
        {
            CanExecuteChangedInternal?.Raise(this);
        }
    }
}
