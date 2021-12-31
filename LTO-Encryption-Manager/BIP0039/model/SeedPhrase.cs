using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.BIP0039
{
    public class SeedPhrase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        private int? length;
        private string? word01;
        private string? word02;
        private string? word03;
        private string? word04;
        private string? word05;
        private string? word06;
        private string? word07;
        private string? word08;
        private string? word09;
        private string? word10;
        private string? word11;
        private string? word12;
        private string? word13;
        private string? word14;
        private string? word15;
        private string? word16;
        private string? word17;
        private string? word18;
        private string? word19;
        private string? word20;
        private string? word21;
        private string? word22;
        private string? word23;
        private string? word24;

        public string? Word01
        {
            get => word01;
            set { word01 = value; OnPropertyChanged(); }
        }
        public string? Word02
        {
            get => word02;
            set { word02 = value; OnPropertyChanged(); }
        }
        public string? Word03
        {
            get => word03;
            set { word03 = value; OnPropertyChanged(); }
        }
        public string? Word04
        {
            get => word04;
            set { word04 = value; OnPropertyChanged(); }
        }
        public string? Word05
        {
            get => word05;
            set { word05 = value; OnPropertyChanged(); }
        }
        public string? Word06
        {
            get => word06;
            set { word06 = value; OnPropertyChanged(); }
        }
        public string? Word07
        {
            get => word07;
            set { word07 = value; OnPropertyChanged(); }
        }
        public string? Word08
        {
            get => word08;
            set { word08 = value; OnPropertyChanged(); }
        }
        public string? Word09
        {
            get => word09;
            set { word09 = value; OnPropertyChanged(); }
        }
        public string? Word10
        {
            get => word10;
            set { word10 = value; OnPropertyChanged(); }
        }
        public string? Word11
        {
            get => word11;
            set { word11 = value; OnPropertyChanged(); }
        }
        public string? Word12
        {
            get => word12;
            set { word12 = value; OnPropertyChanged(); }
        }
        public string? Word13
        {
            get => word13;
            set { word13 = value; OnPropertyChanged(); }
        }
        public string? Word14
        {
            get => word14;
            set { word14 = value; OnPropertyChanged(); }
        }
        public string? Word15
        {
            get => word15;
            set { word15 = value; OnPropertyChanged(); }
        }
        public string? Word16
        {
            get => word16;
            set { word16 = value; OnPropertyChanged(); }
        }
        public string? Word17
        {
            get => word17;
            set { word17 = value; OnPropertyChanged(); }
        }
        public string? Word18
        {
            get => word18;
            set { word18 = value; OnPropertyChanged(); }
        }
        public string? Word19
        {
            get => word19;
            set { word19 = value; OnPropertyChanged(); }
        }
        public string? Word20
        {
            get => word20;
            set { word20 = value; OnPropertyChanged(); }
        }
        public string? Word21
        {
            get => word21;
            set { word21 = value; OnPropertyChanged(); }
        }
        public string? Word22
        {
            get => word22;
            set { word22 = value; OnPropertyChanged(); }
        }
        public string? Word23
        {
            get => word23;
            set { word23 = value; OnPropertyChanged(); }
        }
        public string? Word24
        {
            get => word24;
            set { word24 = value; OnPropertyChanged(); }
        }
        public int? Length
        {
            get { return length; }
            set { length = value; OnPropertyChanged(); }
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

        public SeedPhrase()
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
            if (selectedWord != null && Wallet.Bip0039Dictionaries.AmericanEnglish.TryGetIntFromWord((string)selectedWord, out _))
            {
                word = (string)selectedWord;
            }
            return word != null;
        }

        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
            if (name?.StartsWith("Word", StringComparison.InvariantCulture) == true)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Words)));
            }
        }
    }
}
