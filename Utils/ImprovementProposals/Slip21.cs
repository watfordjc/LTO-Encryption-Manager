using System;
using System.Security.Cryptography;
using System.Text;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals
{
    public static class Slip21
    {
        /// <summary>
        /// Derive a SLIP-0021 master node (m) from a binary master secret.
        /// </summary>
        /// <param name="seedBytes">The binary master secret (e.g. a BIP-0039 binary seed).</param>
        /// <returns>A SLIP-0021 master <see cref="Slip0021Node"/> (m).</returns>
        public static Slip21Node GetMasterNodeFromBinarySeed(in ReadOnlySpan<byte> seedBytes, string globalKeyRolloverCount)
        {
            // SLIP-0021 defines the key for the master node and HMAC-SHA512 as algorithm
            byte[] key = Encoding.UTF8.GetBytes("Symmetric key seed");
            using HMACSHA512 hmac = new(key);
            // Clear array
            Array.Clear(key, 0, key.Length);
            byte[] hashResult = hmac.ComputeHash(seedBytes.ToArray());
            hmac.Clear();
            return new Slip21Node(hashResult, globalKeyRolloverCount);
        }
    }
}
