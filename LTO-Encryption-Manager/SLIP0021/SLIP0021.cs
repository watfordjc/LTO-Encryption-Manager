using System;
using System.Security.Cryptography;
using System.Text;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Wallet
{
    public static class Slip0021
    {
        /// <summary>
        /// Derive a SLIP-0021 master node (m) from a binary master secret.
        /// </summary>
        /// <param name="seedBytes">The binary master secret (e.g. a BIP-0039 binary seed).</param>
        /// <returns>A SLIP-0021 master <see cref="Slip0021Node"/> (m).</returns>
        public static Slip0021Node GetMasterNodeFromBinarySeed(in ReadOnlySpan<byte> seedBytes)
        {
            // SLIP-0021 defines the key for the master node and HMAC-SHA512 as algorithm
            byte[] key = Encoding.UTF8.GetBytes("Symmetric key seed");
            using HMACSHA512 hmac = new(key);
            // Clear array
            Array.Clear(key, 0, key.Length);
            return new Slip0021Node(hmac.ComputeHash(seedBytes.ToArray()));
        }
    }
}
