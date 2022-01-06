using CryptHash.Net.Hash;
using CryptHash.Net.Hash.HashResults;
using System;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Models
{
    public class Slip21ValidationNode
    {
        public event EventHandler<bool>? FingerprintingStarted;
        public event EventHandler<bool>? FingerprintingCompleted;
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
                FingerprintingCompleted?.Invoke(this, true);
            }
        }

        public Slip21ValidationNode(Slip21Node nodeToValidate)
        {
            Slip21Node validationNode = nodeToValidate.GetChildNode(Properties.Resources.slip21_schema_validation).GetChildNode(nodeToValidate.GlobalKeyRolloverCount.ToString(CultureInfo.InvariantCulture));
            DerivationPath = validationNode.DerivationPath;
            // The password/message to hash shall be the right half of the validation node... in Z85 encoding.
            validationNodeMessage = validationNode.Right.ToArray();
            // RFC 9160 Recommendation 1 means the length of the salt is already defined as 16 bytes.
            // These 16 bytes shall be the first 128 bits of the left half of the validation node.
            validationNodeSalt = validationNode.Left.Slice(0, 16).ToArray();
            validationNode.Clear();
        }

        public void CalculateFingerprint()
        {
            if (validationNodeMessage?.Length > 0 && validationNodeSalt?.Length > 0)
            {
                if (Algorithms.Z85.TryGetEncodedBytes(validationNodeMessage, out byte[]? password))
                {
                    CalculateFingerprint(password, validationNodeSalt);
                }
            }
        }

        public async void CalculateFingerprint(byte[] message, byte[] salt)
        {
            if (Fingerprint is not null)
            {
                return;
            }
            Argon2id argon2id = new();
            FingerprintingStarted?.Invoke(this, true);
            Argon2idHashResult argon2IdHashResult = await Task.Run(() => Algorithms.Argon2id.GetKeyValidationHash(argon2id, message, salt, 32)).ConfigureAwait(true);
            Array.Clear(message, 0, message.Length);
            Array.Clear(salt, 0, salt.Length);
            Trace.WriteLine(BitConverter.ToString(argon2IdHashResult.HashBytes));
            if (Algorithms.Z85.TryGetEncodedBytes(argon2IdHashResult.HashBytes, out byte[]? z85Hash))
            {
                Trace.WriteLine(Encoding.UTF8.GetString(z85Hash));
                Fingerprint = Encoding.UTF8.GetString(z85Hash);
            }
        }
    }
}
