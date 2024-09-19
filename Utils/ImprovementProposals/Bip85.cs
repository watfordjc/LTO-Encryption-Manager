using Org.BouncyCastle.Crypto.Digests;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
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

		/// <summary>
		/// Generates BIP39 entropy using BIP85 deterministic BIP39 generation.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 BIP39 derivation path.</param>
		/// <returns>A <see cref="ReadOnlySpan{T}"/> of <see cref="byte"/> containing the derived BIP39 entropy.</returns>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 BIP39 derivation path.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="node"/>'s <see cref="Bip32Node.DerivationPath"/> is not fully hardened, or the <c>words</c>
		///   node has a <see cref="Bip32Node.ChildNumberString"/> that is not 6H/12H/18H/24H/30H/36H/42H/48H.</exception>
		public static ReadOnlySpan<byte> GetBip39Entropy(Bip32Node node)
		{
			// Check required parameters are not null
			ArgumentNullException.ThrowIfNull(node);
			// Extract the parts of the derivation path from the node
			string[] derivationPath = node.DerivationPath.Split('/');
			// Check the derivation path is for a BIP85 HEX node
			if (!node.DerivationPath.StartsWith("m/83696968H/39H/0H/", StringComparison.Ordinal) || derivationPath.Length != 6)
			{
				throw new ArgumentException("Node must be a BIP-0085 BIP39 node using the American English dictionary.", nameof(node));
			}
			// Check all nodes below the root node used hardened derivation
			for (int i = 1; i < derivationPath.Length; i++)
			{
				if (!derivationPath[i].EndsWith('H'))
				{
					throw new ArgumentOutOfRangeException(nameof(node), $"{nameof(node.DerivationPath)} must use hardened derivation for all nodes.");
				}
			}
			// Get the number of words from the derivation path
			int numWords = Int32.Parse(derivationPath[4][..^1], NumberStyles.None, CultureInfo.InvariantCulture);
			int entropyByteLength = numWords switch
			{
				6 => 8,
				12 => 16,
				18 => 24,
				24 => 32,
				30 => 40,
				36 => 48,
				42 => 56,
				48 => 64,
				_ => 0
			};
			if (entropyByteLength == 0)
			{
				throw new ArgumentOutOfRangeException(nameof(node), $"{nameof(node.DerivationPath)} must have a words node with {nameof(Bip32Node.ChildNumberString)} that is 6H/12H/18H/24H/30H/36H/42H/48H - value was {derivationPath[4]}.");
			}
			return GetEntropy(node, entropyByteLength);
		}

		/// <summary>
		/// Generates a <see cref="string"/> using BIP85 deterministic BIP39 generation.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 BIP39 derivation path.</param>
		/// <returns>A deterministic string of hexadecimal characters.</returns>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 BIP39 derivation path.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="node"/>'s <see cref="Bip32Node.DerivationPath"/> is not fully hardened, or the <c>words</c>
		///   node has a <see cref="Bip32Node.ChildNumberString"/> that is not 6H/12H/18H/24H/30H/36H/42H/48H.</exception>
		public static string GetBip39Words(Bip32Node node)
		{
			// Check required parameters are not null
			ArgumentNullException.ThrowIfNull(node);
			// Derive the entropy bytes
			ReadOnlySpan<byte> entropyBytes = GetBip39Entropy(node);
			// Convert the entropy into a BIP39 seed phrase and return it
			return Bip39.GetMnemonicFromEntropy(ByteEncoding.ToHexString(entropyBytes));
		}

		/// <summary>
		/// Get a deterministic <see cref="Bip32Node"/> from a <see cref="Bip32Node"/> that has a BIP-0085 XPRV derivation path.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 XPRV derivation path.</param>
		/// <returns>The derived XPRV as a <see cref="Bip32Node"/> if possible; otherwise, <see langword="null"/>.</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 XPRV derivation path.</exception>
		public static Bip32Node? GetXprv(Bip32Node node)
		{
			ArgumentNullException.ThrowIfNull(node);
			if (!node.DerivationPath.StartsWith("m/83696968H/32H/", StringComparison.Ordinal))
			{
				throw new ArgumentException("Node must have a BIP-0085 XPRV derivation path", nameof(node));
			}
			ReadOnlySpan<byte> entropyBytes = GetEntropy(node, 64);
			ECDomainParameters? domainParams = Bip32.GetDomainParameters((uint)Bip32.PrivateKeyVersionPrefix.BitcoinMainnetPrivate);
			if (domainParams is null)
			{
				return null;
			}
			// BIP85 XPRV swaps Left and Right
			byte[] binarySeed = new byte[64];
			Array.Copy(entropyBytes[..32].ToArray(), 0, binarySeed, 32, 32);
			Array.Copy(entropyBytes[32..].ToArray(), 0, binarySeed, 0, 32);
			return new Bip32Node(binarySeed, domainParams, (uint)Bip32.PublicKeyVersionPrefix.BitcoinMainnetPublic, (uint)Bip32.PrivateKeyVersionPrefix.BitcoinMainnetPrivate,
				null, null, null, null);
		}

		/// <summary>
		/// Generates a <see cref="string"/> using BIP85 deterministic hexadecimal generation.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <returns>A deterministic string of hexadecimal characters.</returns>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 HEX derivation path.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="node"/>'s <see cref="Bip32Node.DerivationPath"/> is not fully hardened, or the <c>num_bytes</c>
		///   node has a <see cref="Bip32Node.ChildNumberString"/> outside the range of 16H to 64H.</exception>
		public static string GetHex(Bip32Node node)
		{
			// Check required parameters are not null
			ArgumentNullException.ThrowIfNull(node);
			// Extract the parts of the derivation path from the node
			string[] derivationPath = node.DerivationPath.Split('/');
			// Check the derivation path is for a BIP85 HEX node
			if (!node.DerivationPath.StartsWith("m/83696968H/128169H/", StringComparison.Ordinal) || derivationPath.Length != 5)
			{
				throw new ArgumentException("Node must be a BIP-0085 HEX node.", nameof(node));
			}
			// Check all nodes below the root node used hardened derivation
			for (int i = 1; i < derivationPath.Length; i++)
			{
				if (!derivationPath[i].EndsWith('H'))
				{
					throw new ArgumentOutOfRangeException(nameof(node), $"{nameof(node.DerivationPath)} must use hardened derivation for all nodes.");
				}
			}
			// Get the number of bytes from the derivation path
			int numBytes = Int32.Parse(derivationPath[3][..^1], NumberStyles.None, CultureInfo.InvariantCulture);
			if (numBytes < 16 || numBytes > 64)
			{
				throw new ArgumentOutOfRangeException(nameof(node), $"{nameof(node.DerivationPath)} has a num_bytes value of {numBytes}H which is outside the range of 16-64.");
			}
			// Get the entropy bytes and convert to hex
			return ByteEncoding.ToHexString(GetEntropy(node, numBytes));
		}

		/// <summary>
		/// Generates a password (Base64 alphabet) using BIP85 deterministic PWD BASE64 generation.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 PWD BASE64 derivation path.</param>
		/// <returns>A deterministic password using the Base64 alphabet.</returns>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 HEX derivation path.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="node"/>'s <see cref="Bip32Node.DerivationPath"/> is not fully hardened, or the <c>pwd_len</c>
		///   node has a <see cref="Bip32Node.ChildNumberString"/> outside the range of 20H to 86H.</exception>
		public static string GetPwdBase64(Bip32Node node)
		{
			// Check required parameters are not null
			ArgumentNullException.ThrowIfNull(node);
			// Extract the parts of the derivation path from the node
			string[] derivationPath = node.DerivationPath.Split('/');
			// Check the derivation path is for a BIP85 PWD BASE64 node
			if (!node.DerivationPath.StartsWith("m/83696968H/707764H/", StringComparison.Ordinal) || derivationPath.Length != 5)
			{
				throw new ArgumentException("Node must be a BIP-0085 PWD BASE64 node.", nameof(node));
			}
			// Check all nodes below the root node used hardened derivation
			for (int i = 1; i < derivationPath.Length; i++)
			{
				if (!derivationPath[i].EndsWith('H'))
				{
					throw new ArgumentOutOfRangeException(nameof(node), $"{nameof(node.DerivationPath)} must use hardened derivation for all nodes.");
				}
			}
			// Get the number of bytes from the derivation path
			int pwdLength = Int32.Parse(derivationPath[3][..^1], NumberStyles.None, CultureInfo.InvariantCulture);
			if (pwdLength < 20 || pwdLength > 86)
			{
				throw new ArgumentOutOfRangeException(nameof(node), $"{nameof(node.DerivationPath)} has a pwd_len value of {pwdLength}H which is outside the range of 20H-86H.");
			}
			// Get the entropy bytes and convert to base64
			string base64 = Convert.ToBase64String(GetEntropy(node, 64), Base64FormattingOptions.None);
			// Return the expected length of characters
			return base64[..pwdLength];
		}

		/// <summary>
		/// Generates an <see cref="RSAParameters"/> instance, if possible, using BIP85 deterministic RSA key generation.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <param name="compatibilityFlags">Compatibility flags that adjust how deterministic prime number and asymmetric key generation is performed.</param>
		/// <param name="rsaParams">An <see cref="RSAParameters"/> instance.</param>
		/// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 RSA derivation path.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="node"/>'s <see cref="Bip32Node.DerivationPath"/> is not fully hardened.</exception>
		public static bool TryCreateStandardRSAParameters(Bip32Node node, StandardRSA.Compatibility compatibilityFlags, [NotNullWhen(true)] out RSAParameters? rsaParams)
		{
			// Check required parameters are not null
			ArgumentNullException.ThrowIfNull(node);
			// Extract the parts of the derivation path from the node
			string[] derivationPath = node.DerivationPath.Split('/');
			// Check the derivation path is for a BIP85 RSA node
			if (!node.DerivationPath.StartsWith("m/83696968H/828365H/", StringComparison.Ordinal) || derivationPath.Length != 5)
			{
				throw new ArgumentException("Node must be a BIP-0085 RSA node.", nameof(node));
			}
			// Check all nodes below the root node used hardened derivation
			for (int i = 1; i < derivationPath.Length; i++)
			{
				if (!derivationPath[i].EndsWith('H'))
				{
					throw new ArgumentOutOfRangeException(nameof(node), $"{nameof(node.DerivationPath)} must use hardened derivation for all nodes.");
				}
			}
			// Get the key/modulus length in bits from the derivation path
			int keyBitLength = Int32.Parse(derivationPath[3][..^1], NumberStyles.None, CultureInfo.InvariantCulture);
			try
			{
				// Use a Shake256Stream seeded using our BIP-0032 node that has a BIP-0085 derivation path
				using Shake256DRNG shake256DRNG = new(node);
				// Create and return an RSAParameters using shake256DRNG as the RNG
				rsaParams = StandardRSA.CreateStandardRSAParameters(keyBitLength, compatibilityFlags, shake256DRNG);
				return true;
			}
			catch (Exception ex) when
			(ex is ArgumentException || ex is UnreachableException)
			{
				rsaParams = null;
				return false;
			}
		}

		/// <summary>
		/// Generates an <see cref="RSA"/> instance, if possible, using BIP85 deterministic RSA key generation.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <param name="compatibilityFlags">Compatibility flags that adjust how deterministic prime number and asymmetric key generation is performed.</param>
		/// <param name="rsa">An <see cref="RSA"/> instance on success; otherwise, <see langword="null"/>.</param>
		/// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have a BIP-0085 RSA derivation path.</exception>
		public static bool TryCreateStandardRSA(Bip32Node node, StandardRSA.Compatibility compatibilityFlags, [NotNullWhen(true)] out RSA? rsa)
		{
			// Check required parameters are not null
			ArgumentNullException.ThrowIfNull(node);

			if (TryCreateStandardRSAParameters(node, compatibilityFlags, out RSAParameters? rsaParams))
			{
				try
				{
					rsa = RSA.Create(rsaParams.Value);
					return true;
				}
				catch (CryptographicException)
				{
					rsa = null;
					return false;
				}
			}
			else
			{
				rsa = null;
				return false;
			}
		}
	}
}
