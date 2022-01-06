using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using uk.JohnCook.dotnet.LTOEncryptionManager.Commands;
using uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.ViewModels
{
    public class AddSeedPhraseViewModel : ViewModelBase
    {
        public List<string>? Bip39Dictionary { get; private set; }
        private Bip39SeedPhrase _newSeedPhrase = new();
        public Bip39SeedPhrase NewSeedPhrase => _newSeedPhrase;
        public SecureString? Passphrase { private get; set; }
        private Slip21Schema _firstLevelLabel;
        public Slip21Schema FirstLevelLabel
        {
            get => _firstLevelLabel;
            set
            {
                _firstLevelLabel = value;
                OnPropertyChanged();
            }
        }
        public List<Slip21Schema> FirstLevelLabels { get; private set; }
        public string GlobalKeyRollovers { get; set; }
        public string DerivationPath { get; set; } = string.Empty;
        public string ValidationFingerprint { get; set; } = string.Empty;
        private readonly ICommand _validateSeedPhrase;
        public ICommand ValidateSeedPhrase => _validateSeedPhrase;
        private Brush _validationStatusBrush = Brushes.Transparent;
        public Brush ValidationStatusBrush
        {
            get => _validationStatusBrush;
            set
            {
                _validationStatusBrush = value;
                OnPropertyChanged();
            }
        }
        private string _validationStatusMessage = string.Empty;
        public string ValidationStatusMessage
        {
            get => _validationStatusMessage;
            set
            {
                _validationStatusMessage = value;
                OnPropertyChanged();
            }
        }

        public AddSeedPhraseViewModel()
        {
            GenerateBip39Dictionary();
            _validateSeedPhrase = new RelayCommand(
                                execute => ValidateSeedPhrase_Execute(),
                                canExecute => !NewSeedPhrase.HasErrors
                                );
            NewSeedPhrase.Length = 24;
            FirstLevelLabels = new()
            {
                new Slip21Schema(Properties.Resources.slip21_schema_lto_aes256gcm),
                new Slip21Schema(Properties.Resources.slip21_schema_snowflake_hmacSha256)
            };
            _firstLevelLabel = FirstLevelLabels[0];
            OnPropertyChanged(nameof(FirstLevelLabel));
            GlobalKeyRollovers = "0";
            NewSeedPhrase.PropertyChanged += new((sender, e) =>
            {
                if (e.PropertyName != nameof(Bip39BinarySeed.ValidationStatusMessage))
                {
                    ValidationStatusMessage = string.Empty;
                }
            });
        }

        private async void GenerateBip39Dictionary()
        {
            Bip39Dictionary = await Bip39.GetWordValues();
        }

        public void ValidateSeedPhrase_Execute()
        {
            Bip39BinarySeed bip39BinarySeed = new(ref _newSeedPhrase);
            if (bip39BinarySeed.TryGetBinarySeed(_newSeedPhrase.HasEmptyPassphrase ? null : Passphrase, out byte[]? binarySeed))
            {
                ValidationStatusBrush = Brushes.Green;
                ValidationStatusMessage = bip39BinarySeed.ValidationStatusMessage;
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(binarySeed, GlobalKeyRollovers);
                Slip21ValidationNode validationNode = new(masterNode.GetChildNode(FirstLevelLabel.FirstLevelLabel).GetChildNode(GlobalKeyRollovers));
                DerivationPath = validationNode.DerivationPath;
                OnPropertyChanged(nameof(DerivationPath));
                validationNode.FingerprintingStarted += new EventHandler<bool>((sender, e) =>
                {
                    if (e)
                    {
                        ValidationFingerprint = "Calculating...";
                        OnPropertyChanged(nameof(ValidationFingerprint));
                    }
                });
                validationNode.FingerprintingCompleted += new EventHandler<bool>((sender, e) =>
                {
                    if (e)
                    {
                        ValidationFingerprint = validationNode.Fingerprint ?? string.Empty;
                        OnPropertyChanged(nameof(ValidationFingerprint));
                    }
                });
                validationNode.CalculateFingerprint();
            }
            else
            {
                ValidationStatusBrush = Brushes.Red;
                ValidationStatusMessage = bip39BinarySeed.ValidationStatusMessage;
                Trace.WriteLine(ValidationStatusMessage);
                DerivationPath = string.Empty;
                OnPropertyChanged(nameof(DerivationPath));
                ValidationFingerprint = string.Empty;
                OnPropertyChanged(nameof(ValidationFingerprint));
            }
        }
    }
}
