using System;
using System.Security.Cryptography;
using System.Text;
using uk.JohnCook.dotnet.LTOEncryptionManager;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Properties;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models
{
    public readonly ref struct Slip21Node
    {
        /// <summary>
        /// The left 32 bytes of the node (the derivation key)
        /// </summary>
        public readonly ReadOnlySpan<byte> Left { get { return nodeBytes.AsSpan()[..32]; } }
        /// <summary>
        /// The right 32 bytes of the node (the symmetric key)
        /// </summary>
        public readonly ReadOnlySpan<byte> Right { get { return nodeBytes.AsSpan()[32..64]; } }
        private readonly byte[] nodeBytes;
        public readonly string DerivationPath { get; init; }
        public readonly string GlobalKeyRolloverCount { get; init; }

        /// <summary>
        /// Instantiate a new SLIP-0021 Node.
        /// </summary>
        /// <param name="nodeBytes">The full 64 bytes of the node (i.e. the first 64 bytes of output from HMAC-SHA512)</param>
        public Slip21Node(byte[] nodeBytes, string globalKeyRolloverCount, string? label = null)
        {
            if (nodeBytes.Length != 64)
            {
                throw new ArgumentException("The byte array must have a length of exactly 64 bytes.", nameof(nodeBytes));
            }
            this.nodeBytes = nodeBytes;
            DerivationPath = label ?? Resources.slip21_master_node_ref;
            GlobalKeyRolloverCount = globalKeyRolloverCount;
        }

        /// <summary>
        /// Get this <see cref="Slip21Node"/>'s child node with label <paramref name="label"/> using derivation key <see cref="Left"/>.
        /// </summary>
        /// <param name="label">The ASCII label for the child node.</param>
        /// <returns>The child <see cref="Slip21Node"/>.</returns>
        public Slip21Node GetChildNode(string label)
        {
            byte[] key = Left.ToArray();
            using HMACSHA512 hmac = new(key);
            // Clear array
            Array.Clear(key, 0, key.Length);
            string derivationPath = string.Concat(DerivationPath, '/', '"', label, '"');
            byte[] hashResult = hmac.ComputeHash(Encoding.ASCII.GetBytes('\0' + label));
            hmac.Clear();
            return new Slip21Node(hashResult, GlobalKeyRolloverCount, derivationPath);
        }

        /// <summary>
        /// Clear/Zero the internal 64-byte <see cref="byte"/>[] array for this <see cref="Slip21Node"/>.
        /// </summary>
        /// <remarks>
        /// <para>Also clears/zeros <see cref="Left"/> and <see cref="Right"/> as they are <see cref="ReadOnlySpan{T}"/>'s of the internal <see cref="byte"/>[] array.</para>
        /// </remarks>
        public void Clear()
        {
            if (nodeBytes is not null)
            {
                Array.Clear(nodeBytes, 0, nodeBytes.Length);
            }
        }
    }
}
