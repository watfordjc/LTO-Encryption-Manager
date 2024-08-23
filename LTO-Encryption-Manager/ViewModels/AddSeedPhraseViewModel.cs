using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security;
using System.Windows.Input;
using System.Windows.Media;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Commands;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.ViewModels
{
	public class AddSeedPhraseViewModel : ViewModelBase
    {
        public Collection<string> Bip39Dictionary { get; private set; }
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
        public Collection<Slip21Schema> FirstLevelLabels { get; private set; }
        public string GlobalKeyRollovers { get; set; }
        public string SeedDerivationPath { get; set; } = string.Empty;
        public string SeedValidationFingerprint { get; set; } = string.Empty;
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
        public string AccountID { get; set; } = string.Empty;
        public string AccountKeyRollovers { get; set; } = string.Empty;
        public string AccountDerivationPath { get; set; } = string.Empty;
        public string AccountValidationFingerprint { get; set; } = string.Empty;

        public AddSeedPhraseViewModel()
        {
			Bip39Dictionary = [];
            GenerateBip39Dictionary();
            _validateSeedPhrase = new RelayCommand(
                                execute => StartValidatingSeedPhrase(),
                                canExecute => !NewSeedPhrase.HasErrors
                                );
            NewSeedPhrase.Length = 24;
            FirstLevelLabels =
			[
				new Slip21Schema(Properties.Resources.slip21_schema_lto_aes256gcm),
                new Slip21Schema(Properties.Resources.slip21_schema_snowflake_hmacSha256)
            ];
            _firstLevelLabel = FirstLevelLabels[0];
            OnPropertyChanged(nameof(FirstLevelLabel));
            GlobalKeyRollovers = "0";
            AccountID = "0";
            AccountKeyRollovers = "0";
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
            await Bip39.GetWordValues(Bip39Dictionary).ConfigureAwait(true);
        }

        public void StartValidatingSeedPhrase()
        {
            Bip39BinarySeed bip39BinarySeed = new(ref _newSeedPhrase);
            if (bip39BinarySeed.TryGetBinarySeed(_newSeedPhrase.HasEmptyPassphrase ? null : Passphrase, out byte[]? binarySeed))
            {
                ValidationStatusBrush = Brushes.Green;
                ValidationStatusMessage = bip39BinarySeed.ValidationStatusMessage;
                Slip21Node masterNode = Slip21.GetMasterNodeFromBinarySeed(binarySeed, GlobalKeyRollovers);
                Slip21ValidationNode validationNode = new(masterNode.GetChildNode(FirstLevelLabel.FirstLevelLabel).GetChildNode(GlobalKeyRollovers));
                SeedDerivationPath = validationNode.DerivationPath;
                OnPropertyChanged(nameof(SeedDerivationPath));
                Slip21Node accountNode = masterNode.GetChildNode(FirstLevelLabel.FirstLevelLabel).GetChildNode(GlobalKeyRollovers).GetChildNode(AccountID).GetChildNode(AccountKeyRollovers);
                Slip21ValidationNode accountValidationNode = new(accountNode);
                AccountDerivationPath = accountValidationNode.DerivationPath;
                OnPropertyChanged(nameof(AccountDerivationPath));
                validationNode.FingerprintingStarted += new EventHandler<FingerprintingStartedEventArgs>((sender, e) =>
                {
                    if (e.HasStarted)
                    {
                        SeedValidationFingerprint = "Calculating...";
                        OnPropertyChanged(nameof(SeedValidationFingerprint));
                    }
                });
                validationNode.FingerprintingCompleted += new EventHandler<FingerprintingCompletedEventArgs>((sender, e) =>
                {
                    if (e.HasCompleted)
                    {
                        SeedValidationFingerprint = validationNode.Fingerprint ?? string.Empty;
                        OnPropertyChanged(nameof(SeedValidationFingerprint));
                        accountValidationNode.CalculateFingerprint();
                    }
                });
                accountValidationNode.FingerprintingStarted += new EventHandler<FingerprintingStartedEventArgs>((sender, e) =>
                {
                    if (e.HasStarted)
                    {
                        AccountValidationFingerprint = "Calculating...";
                        OnPropertyChanged(nameof(AccountValidationFingerprint));
                    }
                });
                accountValidationNode.FingerprintingCompleted += new EventHandler<FingerprintingCompletedEventArgs>((sender, e) =>
                {
                    if (e.HasCompleted)
                    {
                        AccountValidationFingerprint = accountValidationNode.Fingerprint ?? string.Empty;
                        OnPropertyChanged(nameof(AccountValidationFingerprint));
                    }
                });
                validationNode.CalculateFingerprint();
            }
            else
            {
                ValidationStatusBrush = Brushes.Red;
                ValidationStatusMessage = bip39BinarySeed.ValidationStatusMessage;
                Trace.WriteLine(ValidationStatusMessage);
                SeedDerivationPath = string.Empty;
                OnPropertyChanged(nameof(SeedDerivationPath));
                SeedValidationFingerprint = string.Empty;
                OnPropertyChanged(nameof(SeedValidationFingerprint));
                AccountDerivationPath = string.Empty;
                OnPropertyChanged(nameof(AccountDerivationPath));
                AccountValidationFingerprint = string.Empty;
                OnPropertyChanged(nameof(AccountValidationFingerprint));
            }
        }
    }
}
