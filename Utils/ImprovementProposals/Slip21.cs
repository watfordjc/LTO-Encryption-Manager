using System;
using System.Security.Cryptography;
using System.Text;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals
{
	/// <summary>
	/// Provides static methods for working with SLIP-0021.
	/// </summary>
	public static class Slip21
    {
        /// <summary>
        /// Derive a SLIP-0021 master node (m) from a binary master secret.
        /// </summary>
        /// <param name="seedBytes">The binary master secret (e.g. a BIP-0039 binary seed).</param>
        /// <param name="globalKeyRolloverCount">The global key rollover count, as a string.</param>
        /// <returns>A master <see cref="Slip21Node"/> (m).</returns>
        public static Slip21Node GetMasterNodeFromBinarySeed(in ReadOnlySpan<byte> seedBytes, string globalKeyRolloverCount)
        {
            // SLIP-0021 defines the key for the master node and HMAC-SHA512 as algorithm
            byte[] key = Encoding.UTF8.GetBytes("Symmetric key seed");
            byte[] hashResult = HMACSHA512.HashData(key, seedBytes);
            return new Slip21Node(hashResult, globalKeyRolloverCount);
        }
    }
}
