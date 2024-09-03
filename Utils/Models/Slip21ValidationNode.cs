using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Properties;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
    public class FingerprintingStartedEventArgs(bool hasStarted) : EventArgs
    {
		public bool HasStarted { get; init; } = hasStarted;
	}

	public class FingerprintingCompletedEventArgs(bool hasCompleted) : EventArgs
    {
		public bool HasCompleted { get; init; } = hasCompleted;
	}

    public class Slip21ValidationNode
    {
        public event EventHandler<FingerprintingStartedEventArgs>? FingerprintingStarted;
        public event EventHandler<FingerprintingCompletedEventArgs>? FingerprintingCompleted;
        private readonly byte[]? validationNodeMessage;
        private readonly byte[]? validationNodeSalt;
        public string DerivationPath { get; init; }
        private string? _fingerprint;
        public string? Fingerprint
        {
            get => _fingerprint;
            private set
            {
                _fingerprint = value;
                FingerprintingCompleted?.Invoke(this, new(true));
            }
        }

        public Slip21ValidationNode(Slip21Node nodeToValidate)
        {
            Slip21Node validationNode = nodeToValidate.GetChildNode(Resources.slip21_schema_validation).GetChildNode(nodeToValidate.GlobalKeyRolloverCount.ToString(CultureInfo.InvariantCulture));
            DerivationPath = validationNode.DerivationPath;
            // The password/message to hash shall be the right half of the validation node... in Z85 encoding.
            validationNodeMessage = [.. validationNode.Right];
            // RFC 9160 Recommendation 1 means the length of the salt is already defined as 16 bytes.
            // These 16 bytes shall be the first 128 bits of the left half of the validation node.
            validationNodeSalt = [.. validationNode.Left[..16]];
            validationNode.Clear();
        }

        public void CalculateFingerprint(int argon2idOutputLength = 32)
        {
            if (validationNodeMessage?.Length > 0 && validationNodeSalt?.Length > 0)
            {
                if (Encodings.TryGetToZ85Encoded(validationNodeMessage, out byte[]? password))
                {
                    CalculateFingerprint(password, validationNodeSalt, argon2idOutputLength);
                }
            }
        }

        public async void CalculateFingerprint(byte[] message, byte[] salt, int argon2idOutputLength = 32)
        {
            ArgumentNullException.ThrowIfNull(message);
            ArgumentNullException.ThrowIfNull(salt);
            if (Fingerprint is not null)
            {
                return;
            }
            Argon2id argon2id = new();
            FingerprintingStarted?.Invoke(this, new(true));
            Argon2idHashResult argon2IdHashResult = await Task.Run(() => Algorithms.Argon2id.GetKeyValidationHash(argon2id, message, salt, argon2idOutputLength)).ConfigureAwait(true);
            Array.Clear(message, 0, message.Length);
            Array.Clear(salt, 0, salt.Length);
            //Trace.WriteLine(BitConverter.ToString(argon2IdHashResult.HashBytes));
            if (Encodings.TryGetToZ85Encoded(argon2IdHashResult.HashBytes, out byte[]? z85Hash))
            {
                //Trace.WriteLine(DerivationPath);
                //Trace.WriteLine(Encoding.UTF8.GetString(z85Hash));
                Fingerprint = Encoding.UTF8.GetString(z85Hash);
            }
        }
    }
}
