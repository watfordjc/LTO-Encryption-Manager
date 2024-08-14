using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
    public class Bip39SeedPhrase : INotifyPropertyChanged, INotifyDataErrorInfo
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        public event EventHandler<DataErrorsChangedEventArgs>? ErrorsChanged;

        private readonly ObservableCollection<int> _words = [];
        public ReadOnlyObservableCollection<int> Words { get; init; }
        private readonly Dictionary<string, List<string>> _errorsByPropertyName12 = [];
        private readonly Dictionary<string, List<string>> _errorsByPropertyName18 = [];
        private readonly Dictionary<string, List<string>> _errorsByPropertyName24 = [];
        private readonly Dictionary<string, List<string>> _errorsByPropertyNameOther = [];
        private readonly Dictionary<string, List<string>> _errorsByPropertyName = [];
        public bool HasErrors
        {
            get
            {
                return Length switch
                {
                    12 => _errorsByPropertyName12.Count != 0 || _errorsByPropertyNameOther.Count != 0,
                    18 => _errorsByPropertyName18.Count != 0 || _errorsByPropertyNameOther.Count != 0,
                    24 => _errorsByPropertyName24.Count != 0 || _errorsByPropertyNameOther.Count != 0,
                    _ => _errorsByPropertyName.Count != 0
				};
            }
        }
        private bool _hasEmptyPassphrase = true;
        public bool HasEmptyPassphrase
        {
            get => _hasEmptyPassphrase;
            set
            {
                _hasEmptyPassphrase = value;
                NotifyPropertyChanged();
            }
        }

        public int Word01
        {
            get => _words[0];
            set
            {
                _words[0] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word02
        {
            get => _words[1];
            set
            {
                _words[1] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word03
        {
            get => _words[2];
            set
            {
                _words[2] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word04
        {
            get => _words[3];
            set
            {
                _words[3] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word05
        {
            get => _words[4];
            set
            {
                _words[4] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word06
        {
            get => _words[5];
            set
            {
                _words[5] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word07
        {
            get => _words[6];
            set
            {
                _words[6] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word08
        {
            get => _words[7];
            set
            {
                _words[7] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word09
        {
            get => _words[8];
            set
            {
                _words[8] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word10
        {
            get => _words[9];
            set
            {
                _words[9] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word11
        {
            get => _words[10];
            set
            {
                _words[10] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word12
        {
            get => _words[11];
            set
            {
                _words[11] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word13
        {
            get => _words[12];
            set
            {
                _words[12] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word14
        {
            get => _words[13];
            set
            {
                _words[13] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word15
        {
            get => _words[14];
            set
            {
                _words[14] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word16
        {
            get => _words[15];
            set
            {
                _words[15] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word17
        {
            get => _words[16];
            set
            {
                _words[16] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word18
        {
            get => _words[17];
            set
            {
                _words[17] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word19
        {
            get => _words[18];
            set
            {
                _words[18] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word20
        {
            get => _words[19];
            set
            {
                _words[19] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word21
        {
            get => _words[20];
            set
            {
                _words[20] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word22
        {
            get => _words[21];
            set
            {
                _words[21] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word23
        {
            get => _words[22];
            set
            {
                _words[22] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        public int Word24
        {
            get => _words[23];
            set
            {
                _words[23] = value;
                NotifyPropertyChanged();
                ValidateWord(value);
            }
        }
        private int _length;
        public int Length
        {
            get => _length;
            set
            {
                _length = value;
                NotifyPropertyChanged();
                ValidateLength();
            }
        }

        public Bip39SeedPhrase()
        {
            for (int i = 0; i < 24; ++i)
            {
                _words.Add(-1);
                string propertyName = $"Word{i + 1:00}";
                ValidateWord(_words[i], propertyName);
            }
            Words = new(_words);
        }

        private void ValidateWord(int value, [CallerMemberName] string? propertyName = null)
        {
            if (propertyName is null)
            {
                return;
            }
            switch (value)
            {
                case >= 0 and <= 2047:
                    ClearErrors(propertyName);
                    return;
                default:
                    AddError(propertyName, "Word not in American English BIP39 Dictionary.");
                    break;
            }
        }

        private void ValidateLength()
        {
            switch (Length)
            {
                case 12:
                case 18:
                case 24:
                    return;
                default:
                    AddError(nameof(Length), "Seed phrase length must be 12, 18, or 24 words.");
                    break;
            }
        }

        private void AddError(string propertyName, string error)
        {
            if (propertyName.StartsWith("Word") && int.TryParse(propertyName.AsSpan(4, 2), out int wordNumber))
            {
                if (!_errorsByPropertyName.TryGetValue(propertyName, out List<string>? value))
                {
					value = [];
					_errorsByPropertyName[propertyName] = value;
                    if (wordNumber <= 12)
                    {
                        _errorsByPropertyName12[propertyName] = [];
                    }
                    if (wordNumber <= 18)
                    {
                        _errorsByPropertyName18[propertyName] = [];
                    }
                    if (wordNumber <= 24)
                    {
                        _errorsByPropertyName24[propertyName] = [];
                    }
                }
                if (wordNumber <= 12 && !_errorsByPropertyName12[propertyName].Contains(error))
                {
                    _errorsByPropertyName12[propertyName].Add(error);
                }
                if (wordNumber <= 18 && !_errorsByPropertyName18[propertyName].Contains(error))
                {
                    _errorsByPropertyName18[propertyName].Add(error);
                }
                if (wordNumber <= 24 && !_errorsByPropertyName24[propertyName].Contains(error))
                {
                    _errorsByPropertyName24[propertyName].Add(error);
                }
                if (!value.Contains(error))
                {
					value.Add(error);
                    OnErrorsChanged(propertyName);
                }
            }
            else
            {
                if (!_errorsByPropertyName.TryGetValue(propertyName, out List<string>? value))
                {
					value = [];
					_errorsByPropertyName[propertyName] = value;
                    _errorsByPropertyNameOther[propertyName] = [];
                }
                if (!_errorsByPropertyNameOther[propertyName].Contains(error))
                {
                    _errorsByPropertyNameOther[propertyName].Add(error);
                }
                if (!value.Contains(error))
                {
					value.Add(error);
                    OnErrorsChanged(propertyName);
                }
            }
        }

        private void ClearErrors(string propertyName)
        {
            if (_errorsByPropertyName12.ContainsKey(propertyName))
            {
                _ = _errorsByPropertyName12.Remove(propertyName);
            }
            if (_errorsByPropertyName18.ContainsKey(propertyName))
            {
                _ = _errorsByPropertyName18.Remove(propertyName);
            }
            if (_errorsByPropertyName24.ContainsKey(propertyName))
            {
                _ = _errorsByPropertyName24.Remove(propertyName);
            }
            if (_errorsByPropertyNameOther.ContainsKey(propertyName))
            {
                _ = _errorsByPropertyNameOther.Remove(propertyName);
            }
            if (_errorsByPropertyName.ContainsKey(propertyName))
            {
                _ = _errorsByPropertyName.Remove(propertyName);
                OnErrorsChanged(propertyName);
            }
        }

        private void OnErrorsChanged(string propertyName)
        {
            ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(propertyName));
        }

        public IEnumerable GetErrors(string? propertyName)
        {
            return string.IsNullOrEmpty(propertyName)
                ? _errorsByPropertyName
                : _errorsByPropertyName.TryGetValue(propertyName, out List<string>? value) ? value : Enumerable.Empty<string>();
        }

        protected void NotifyPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
