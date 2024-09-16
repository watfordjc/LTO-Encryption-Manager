using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals
{
	/// <summary>
	/// Provides static methods for working with BIP-0085.
	/// </summary>
	public static class Bip85
	{
		/// <summary>
		/// Get up to 64 bytes of determinstic entropy from a <see cref="Bip32Node"/> that has a BIP-0085 derivation path.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <param name="requestedBytes">The number of bytes of entropy required (range: 1-64).</param>
		/// <returns>The requested number of bytes of deterministic entropy.</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 derivation path.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="requestedBytes"/> is outside of the permitted range (1-64 bytes).</exception>
		public static ReadOnlySpan<byte> GetEntropy(Bip32Node node, int requestedBytes)
		{
			ArgumentNullException.ThrowIfNull(node);
			if (!node.DerivationPath.StartsWith("m/83696968H/", StringComparison.Ordinal))
			{
				throw new ArgumentException("Node must have a BIP-0085 derivation path", nameof(node));
			}
			else if (requestedBytes <= 0)
			{
				throw new ArgumentOutOfRangeException($"Parameter {nameof(requestedBytes)} value of {requestedBytes} is not at least 1.");
			}
			else if (requestedBytes > HMACSHA512.HashSizeInBytes)
			{
				throw new ArgumentOutOfRangeException($"Parameter {nameof(requestedBytes)} value of {requestedBytes} exceeds maximum of {HMACSHA512.HashSizeInBytes}.");
			}
			byte[] hmacKey = Encoding.UTF8.GetBytes("bip-entropy-from-k");
			return HMACSHA512.HashData(hmacKey, node.Left).AsSpan(0, requestedBytes);
		}

		/// <summary>
		/// Get a specified amount of deterministic entropy from a <see cref="Bip32Node"/> that has a BIP-0085 derivation path.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <param name="requestedBytes">The number of bytes of entropy required (minimum: 1).</param>
		/// <returns>The requested number of bytes of deterministic entropy if possible, else an empty byte array.</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 derivation path.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="requestedBytes"/> is outside of the permitted range (1+ bytes).</exception>
		public static ReadOnlySpan<byte> GetShake256Entropy(Bip32Node node, int requestedBytes)
		{
			ArgumentNullException.ThrowIfNull(node);
			if (!node.DerivationPath.StartsWith("m/83696968H/", StringComparison.Ordinal))
			{
				throw new ArgumentException("Node must have a BIP-0085 derivation path", nameof(node));
			}
			else if (requestedBytes < 1)
			{
				throw new ArgumentOutOfRangeException($"Parameter {nameof(requestedBytes)} value of {requestedBytes} is not at least 1.");
			}
			// Get the Shake256 seed bytes using BIP85
			ReadOnlySpan<byte> inputEntropy = GetEntropy(node, HMACSHA512.HashSizeInBytes);
			// Use .NET implementation of SHAKE-256 on supported operating systems
			if (Shake256.IsSupported)
			{
				return Shake256.HashData(inputEntropy, requestedBytes);
			}
			// Otherwise, use BouncyCastle implementation of SHAKE-256
			else
			{
				// Create a SHAKE-256 instance
				ShakeDigest shakeDigest = new(256);
				// Feed in the input entropy
				shakeDigest.BlockUpdate([.. inputEntropy], 0, HMACSHA512.HashSizeInBytes);
				// Create a byte array for the output entropy
				byte[] outputEntropy = new byte[requestedBytes];
				// Try to get the requested amount of output entropy
				int outputBytes = shakeDigest.OutputFinal(outputEntropy);
				// Return the output entropy if it is of the requested length
				return outputBytes == requestedBytes ? outputEntropy : [];
			}
		}
	}
}
