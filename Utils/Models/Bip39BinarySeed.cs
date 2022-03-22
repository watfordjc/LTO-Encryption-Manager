using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
    public class Bip39BinarySeed : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        private string _validationStatusMessage = string.Empty;
        public string ValidationStatusMessage
        {
            get => _validationStatusMessage;
            set
            {
                _validationStatusMessage = value;
                NotifyPropertyChanged();
            }
        }
        private readonly Bip39SeedPhrase seedPhrase;

        public Bip39BinarySeed(ref Bip39SeedPhrase seedPhrase)
        {
            this.seedPhrase = seedPhrase;
        }

        public bool TryGetBinarySeed(SecureString? passphrase, [NotNullWhen(true)] out byte[]? binarySeed)
        {
            binarySeed = null;
            string[] seedWords = new string[seedPhrase.Length];
            for (int i = 0; i < seedPhrase.Length; i++)
            {
                switch (seedPhrase.Words[i])
                {
                    case < 0 or > 2047:
                        return false;
                    default:
                        {
                            string? seedWord = Bip39.GetWordValue(seedPhrase.Words[i])?.FirstOrDefault();
                            if (string.IsNullOrEmpty(seedWord))
                            {
                                return false;
                            }
                            else
                            {
                                seedWords[i] = seedWord;
                            }

                            break;
                        }
                }
            }

            try
            {
                _ = Bip39.GetEntropyBytesFromSeedWords(ref seedWords);
                binarySeed = Bip39.GetBinarySeedFromSeedWords(ref seedWords, passphrase);
                ValidationStatusMessage = "Seed Phrase is Valid";
                return true;
            }
            catch (ArgumentException ae)
            {
                ValidationStatusMessage = ae.Message;
                return false;
            }
        }

        protected void NotifyPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
