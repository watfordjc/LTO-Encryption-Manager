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
    /// <summary>
    /// Event arguments for <see cref="Slip21ValidationNode.FingerprintingStarted"/>.
    /// </summary>
    /// <param name="hasStarted">Used to indicate whether fingerprinting has started.</param>
    public class FingerprintingStartedEventArgs(bool hasStarted) : EventArgs
    {
        /// <summary>
        /// Indicates whether fingerprinting has started.
        /// </summary>
		public bool HasStarted { get; init; } = hasStarted;
	}

	/// <summary>
	/// Event arguments for <see cref="Slip21ValidationNode.FingerprintingCompleted"/>.
	/// </summary>
	/// <param name="hasCompleted">Used to indicate whether fingerprinting has completed.</param>
	public class FingerprintingCompletedEventArgs(bool hasCompleted) : EventArgs
    {
        /// <summary>
        /// Indicates whether fingerprinting has completed.
        /// </summary>
		public bool HasCompleted { get; init; } = hasCompleted;
	}

    /// <summary>
    /// A SLIP-0021 validation node.
    /// </summary>
    public class Slip21ValidationNode
    {
        /// <summary>
        /// An event fired when fingerprinting of this node has started.
        /// </summary>
        public event EventHandler<FingerprintingStartedEventArgs>? FingerprintingStarted;
        /// <summary>
        /// An event fired when fingerprinting of this node has completed.
        /// </summary>
        public event EventHandler<FingerprintingCompletedEventArgs>? FingerprintingCompleted;
        private readonly byte[]? validationNodeMessage;
        private readonly byte[]? validationNodeSalt;
        /// <summary>
        /// The derivation path of this validation node.
        /// </summary>
        public string DerivationPath { get; init; }
        private string? _fingerprint;
        /// <summary>
        /// The calculated fingerprint of this node.
        /// </summary>
        public string? Fingerprint
        {
            get => _fingerprint;
            private set
            {
                _fingerprint = value;
                FingerprintingCompleted?.Invoke(this, new(true));
            }
        }

        /// <summary>
        /// Creates a <see cref="Slip21ValidationNode"/> from a <see cref="Slip21Node"/>.
        /// </summary>
        /// <param name="nodeToValidate">The <see cref="Slip21Node"/> to create a validation node for.</param>
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

		/// <summary>
		/// Calculates the fingerprint for this <see cref="Slip21ValidationNode"/> object.
		/// </summary>
		/// <param name="argon2idOutputLength">The desired length of the <see cref="Fingerprint"/>, in bytes.</param>
		public void CalculateFingerprint(int argon2idOutputLength = 32)
        {
            if (validationNodeMessage?.Length > 0 && validationNodeSalt?.Length > 0)
            {
                if (ByteEncoding.TryGetToZ85Encoded(validationNodeMessage, out char[]? password))
                {
                    CalculateFingerprint(Encoding.UTF8.GetBytes(password), validationNodeSalt, argon2idOutputLength);
                }
            }
        }

		/// <summary>
		/// Calculates the fingerprint for this <see cref="Slip21ValidationNode"/>.
		/// </summary>
		/// <param name="message">The message to use with <see cref="Argon2id"/>.</param>
		/// <param name="salt">The salt to use with <see cref="Argon2id"/>.</param>
		/// <param name="argon2idOutputLength">The desired length of the <see cref="Fingerprint"/>, in bytes.</param>
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
            if (ByteEncoding.TryGetToZ85Encoded(argon2IdHashResult.HashBytes, out char[]? z85Hash))
            {
                //Trace.WriteLine(DerivationPath);
                //Trace.WriteLine(Encoding.UTF8.GetString(z85Hash));
                Fingerprint = new string(z85Hash);
            }
        }
    }
}
