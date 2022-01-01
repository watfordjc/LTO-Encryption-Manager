using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals.Models
{
    public class Bip39SeedPhrase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        private string? _word01;
        private string? _word02;
        private string? _word03;
        private string? _word04;
        private string? _word05;
        private string? _word06;
        private string? _word07;
        private string? _word08;
        private string? _word09;
        private string? _word10;
        private string? _word11;
        private string? _word12;
        private string? _word13;
        private string? _word14;
        private string? _word15;
        private string? _word16;
        private string? _word17;
        private string? _word18;
        private string? _word19;
        private string? _word20;
        private string? _word21;
        private string? _word22;
        private string? _word23;
        private string? _word24;
        private int? _length;
        private bool _dataChanged;

        public string? Word01
        {
            get => _word01;
            set { _word01 = value; OnPropertyChanged(); }
        }
        public string? Word02
        {
            get => _word02;
            set { _word02 = value; OnPropertyChanged(); }
        }
        public string? Word03
        {
            get => _word03;
            set { _word03 = value; OnPropertyChanged(); }
        }
        public string? Word04
        {
            get => _word04;
            set { _word04 = value; OnPropertyChanged(); }
        }
        public string? Word05
        {
            get => _word05;
            set { _word05 = value; OnPropertyChanged(); }
        }
        public string? Word06
        {
            get => _word06;
            set { _word06 = value; OnPropertyChanged(); }
        }
        public string? Word07
        {
            get => _word07;
            set { _word07 = value; OnPropertyChanged(); }
        }
        public string? Word08
        {
            get => _word08;
            set { _word08 = value; OnPropertyChanged(); }
        }
        public string? Word09
        {
            get => _word09;
            set { _word09 = value; OnPropertyChanged(); }
        }
        public string? Word10
        {
            get => _word10;
            set { _word10 = value; OnPropertyChanged(); }
        }
        public string? Word11
        {
            get => _word11;
            set { _word11 = value; OnPropertyChanged(); }
        }
        public string? Word12
        {
            get => _word12;
            set { _word12 = value; OnPropertyChanged(); }
        }
        public string? Word13
        {
            get => _word13;
            set { _word13 = value; OnPropertyChanged(); }
        }
        public string? Word14
        {
            get => _word14;
            set { _word14 = value; OnPropertyChanged(); }
        }
        public string? Word15
        {
            get => _word15;
            set { _word15 = value; OnPropertyChanged(); }
        }
        public string? Word16
        {
            get => _word16;
            set { _word16 = value; OnPropertyChanged(); }
        }
        public string? Word17
        {
            get => _word17;
            set { _word17 = value; OnPropertyChanged(); }
        }
        public string? Word18
        {
            get => _word18;
            set { _word18 = value; OnPropertyChanged(); }
        }
        public string? Word19
        {
            get => _word19;
            set { _word19 = value; OnPropertyChanged(); }
        }
        public string? Word20
        {
            get => _word20;
            set { _word20 = value; OnPropertyChanged(); }
        }
        public string? Word21
        {
            get => _word21;
            set { _word21 = value; OnPropertyChanged(); }
        }
        public string? Word22
        {
            get => _word22;
            set { _word22 = value; OnPropertyChanged(); }
        }
        public string? Word23
        {
            get => _word23;
            set { _word23 = value; OnPropertyChanged(); }
        }
        public string? Word24
        {
            get => _word24;
            set { _word24 = value; OnPropertyChanged(); }
        }
        public int? Length
        {
            get => _length;
            set { _length = value; OnPropertyChanged(); }
        }
        public string[]? Words
        {
            get
            {
                if (Length is null)
                {
                    return null;
                }
                else
                {
                    string[] seedWords = new string[(int)Length];
                    for (int i = 0; i < Length; i++)
                    {
                        if (TryGetSelectedWord(i + 1, out string? currentWord))
                        {
                            seedWords[i] = currentWord;
                        }
                        else
                        {
                            return null;
                        }
                    }
                    return seedWords;
                }
            }
        }

        public bool DataHasChanged
        {
            get => _dataChanged;
            set
            {
                _dataChanged = value;
                OnPropertyChanged();
            }
        }

        public Bip39SeedPhrase()
        {
            Length = 24;
        }

        private bool TryGetSelectedWord(int selectedWordIndex, [NotNullWhen(true)] out string? word)
        {
            word = null;
            object? selectedWord = selectedWordIndex switch
            {
                1 => Word01,
                2 => Word02,
                3 => Word03,
                4 => Word04,
                5 => Word05,
                6 => Word06,
                7 => Word07,
                8 => Word08,
                9 => Word09,
                10 => Word10,
                11 => Word11,
                12 => Word12,
                13 => Word13,
                14 => Word14,
                15 => Word15,
                16 => Word16,
                17 => Word17,
                18 => Word18,
                19 => Word19,
                20 => Word20,
                21 => Word21,
                22 => Word22,
                23 => Word23,
                24 => Word24,
                _ => null
            };
            if (selectedWord != null && BIP39Dictionaries.AmericanEnglish.TryGetIntFromWord((string)selectedWord, out _))
            {
                word = (string)selectedWord;
            }
            return word != null;
        }

        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
            if (name is not null and not (nameof(DataHasChanged)))
            {
                DataHasChanged = true;
            }
            if (name?.StartsWith("Word", StringComparison.InvariantCulture) == true)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Words)));
            }
        }
    }
}
