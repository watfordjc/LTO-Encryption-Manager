using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using static uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Bip32;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models
{
	/// <summary>
	/// Provides static methods and variables for working with BIP-0032.
	/// </summary>
	static class Bip32Utils
	{
		/// <summary>
		/// A 32-byte array containing zeros.
		/// </summary>
		public static byte[] Zeroed32ByteArray = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
	}

	/// <summary>
	/// A BIP-0032 node, such as a master node, parent node, or child node.
	/// </summary>
	public class Bip32Node
	{
		/// <summary>
		/// The left 32 bytes of this node (the private key).
		/// </summary>
		public ReadOnlySpan<byte> Left { get { return NodeBytes.AsSpan()[..32]; } }
		/// <summary>
		/// The right 32 bytes of this node (the chain code).
		/// </summary>
		private ReadOnlySpan<byte> Right { get { return NodeBytes.AsSpan()[32..64]; } }
		/// <summary>
		/// The 64 bytes of this node (Left || Right).
		/// </summary>
		private byte[] NodeBytes { get; init; } = [];
		/// <summary>
		/// The BIP-0032 version prefix for a public key, as a <see cref="uint"/> (host byte order).
		/// </summary>
		public uint? VersionPrefixPublic { get; init; }
		/// <summary>
		/// The BIP-0032 version prefix for a private key, as a <see cref="uint"/> (host byte order).
		/// </summary>
		public uint? VersionPrefixPrivate { get; init; }
		/// <summary>
		/// This node's derivation path.
		/// </summary>
		public string DerivationPath { get; set; } = string.Empty;
		/// <summary>
		/// This node's depth. A master/root node has a depth of 0.
		/// </summary>
		public byte Depth { get; init; }
		/// <summary>
		/// This node's parent's fingerprint if known/applicable; otherwise, <see langword="null"/>.
		/// </summary>
		public uint? ParentFingerprint { get; init; }
		/// <summary>
		/// If this node is child of a parent node, its child number (index) if known; otherwise, <see langword="null"/>.
		/// </summary>
		public uint? ChildNumber { get; init; }
		/// <summary>
		/// The string representation of <seealso cref="ChildNumber"/>.
		/// </summary>
		/// <remarks>Note: Hardened nodes have an <c>H</c> suffix.</remarks>
		public string ChildNumberString => IsMasterNode ? string.Empty : IsHardenedNode ? string.Format(CultureInfo.InvariantCulture, "{0}H", ChildNumber - 0x8000_0000) : ChildNumber?.ToString(CultureInfo.InvariantCulture) ?? string.Empty;
		/// <summary>
		/// Whether this node was created using hardened derivation.
		/// </summary>
		public bool IsHardenedNode => IsMasterNode || ChildNumber >= 0x8000_0000;
		/// <summary>
		/// Whether this node is a master/root node.
		/// </summary>
		public bool IsMasterNode { get; init; }
		/// <summary>
		/// This node's public key identifier (hex).
		/// </summary>
		public string? KeyIdentifier { get; init; }
		/// <summary>
		/// This node's fingerprint (hex).
		/// </summary>
		public uint? Fingerprint { get; init; }
		/// <summary>
		/// This node's public key.
		/// </summary>
		private ECPublicKeyParameters? PublicKey { get; init; }
		/// <summary>
		/// This node's serialised public key.
		/// </summary>
		public string? PublicKeySerialised { get; init; }
		/// <summary>
		/// This node's private key.
		/// </summary>
		private ECPrivateKeyParameters? PrivateKey { get; init; }
		/// <summary>
		/// This node's serialised private key.
		/// </summary>
		public string? PrivateKeySerialised { get; init; }
		/// <summary>
		/// Whether this node has been initialised successfully.
		/// </summary>
		public bool IsInitialised { get; init; }

		/// <summary>
		/// Instantiate a new BIP-0032 node from a byte array containing the node's entropy.
		/// </summary>
		/// <param name="nodeBytes">The full 64 bytes of the node (i.e. the first 64 bytes of output from HMAC-SHA512)</param>
		/// <param name="domainParams">The domain parameters of the curve.</param>
		/// <param name="versionBytesPublic">The BIP-0032 version prefix for public keys.</param>
		/// <param name="versionBytesPrivate">The BIP-0032 version prefix for private keys.</param>
		/// <param name="parentDerivationPath">The derivation path of the parent node if known; <see langword="null"/> if unknown or creating a master/root node (m).</param>
		/// <param name="parentDepth">The depth of the parent node if known; <see langword="null"/> if unknown or creating a master/root node (m).</param>
		/// <param name="parentFingerprint">The public key fingerprint of the parent node if known; <see langword="null"/> if unknown or creating a master/root node (m).</param>
		/// <param name="childNumber">The child number of the parent node, or <see langword="null"/> if creating a master/root node (m).</param>
		public Bip32Node(byte[] nodeBytes, ECDomainParameters domainParams, uint? versionBytesPublic, uint? versionBytesPrivate, string? parentDerivationPath, byte? parentDepth, uint? parentFingerprint, uint? childNumber)
		{
			ArgumentNullException.ThrowIfNull(nodeBytes);
			ArgumentNullException.ThrowIfNull(domainParams);
			if (parentDerivationPath is null || parentDepth is null || parentFingerprint is null || childNumber is null)
			{
				if (parentDerivationPath is not null || parentDepth is not null || parentFingerprint is not null || childNumber is not null)
				{
					throw new ArgumentException("One or more parent/child parameters is null which is only allowed for a master node, where all parent/child parameters must be null.");
				}
				else
				{
					IsMasterNode = true;
				}
			}
			if (nodeBytes.Length != 64)
			{
				throw new ArgumentException("The byte array must have a length of exactly 64 bytes.", nameof(nodeBytes));
			}
			if (versionBytesPublic is null && versionBytesPrivate is null)
			{
				throw new ArgumentException("Version prefix cannot be null.");
			}

			VersionPrefixPublic = versionBytesPublic;
			VersionPrefixPrivate = versionBytesPrivate;
			NodeBytes = nodeBytes;
			Depth = (byte)(parentDepth + 1 ?? 0);
			ParentFingerprint = parentFingerprint;
			ChildNumber = IsMasterNode ? null : childNumber;
			DerivationPath = IsMasterNode ? "m" : string.Format(CultureInfo.InvariantCulture, "{0}/{1}", parentDerivationPath, ChildNumberString);

			// Create the private key
			PrivateKey = CalculateECPrivateKey(domainParams, [.. Left]);
			// Create the public key
			PublicKey = CalculateECPublicKey(domainParams, PrivateKey);
			bool serialisePrivSuccess = TryCalculateSerialisedPrivateKey(PrivateKey, out string? privKeySerialised);
			bool serialisePubSuccess = TryCalculateSerialisedPublicKey(PublicKey, out string? keyIdentifier, out string? pubKeySerialised);

			if (serialisePrivSuccess && serialisePubSuccess)
			{
				KeyIdentifier = keyIdentifier;
				Fingerprint = KeyIdentifier is null ? null : BitConverter.ToUInt32(Utils.ByteEncoding.FromNetworkByteOrderHexString(KeyIdentifier[..8]));
				PrivateKeySerialised = privKeySerialised;
				PublicKeySerialised = pubKeySerialised;
				IsInitialised = true;
			}
			else
			{
				throw new CryptographicException("An error occured whilst serialising keys.");
			}
		}

		/// <summary>
		/// Instantiate a BIP-0032 node from a serialised key.
		/// </summary>
		/// <param name="serialisedKey">The serialised representation of the private/public key.</param>
		/// <param name="nodeDerivationPath">The node's derivation path, or <see langword="null"/> if not known.</param>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">Thrown if the <paramref name="serialisedKey"/> is invalid, or if its BIP-0032 private/public key prefix is not known.</exception>
		/// <exception cref="CryptographicException">Thrown if an error occurred during node creation whilst (re-)serialising the private and/or public key.</exception>
		public Bip32Node(string serialisedKey, string? nodeDerivationPath = null)
		{
			ArgumentNullException.ThrowIfNull(serialisedKey);
			// Deserialise the key
			byte[] deserialisedKey = ByteEncoding.GetBase256FromBase58String(Encoding.UTF8.GetBytes(serialisedKey).AsSpan());
			// If deserialisation fails, return early
			if (deserialisedKey == null)
			{
				Clear();
				throw new ArgumentNullException(nameof(serialisedKey));
			}
			else if (!ByteEncoding.VerifyBase58CheckChecksum(deserialisedKey))
			{
				Clear();
				throw new ArgumentException("Base58Check checksum check failed.", nameof(serialisedKey));
			}
			// The first 4 bytes are the version bytes, in network byte order
			uint versionPrefix = GetHostUInt32FromNetworkBytes(deserialisedKey[..4]);
			ECDomainParameters? domainParams = GetDomainParameters(versionPrefix);
			if (domainParams is null)
			{
				Clear();
				throw new ArgumentException("Unknown version byte value.", nameof(serialisedKey));
			}
			// The next byte is the node's depth
			Depth = deserialisedKey[4];
			// If the depth is 0, it is a master node
			IsMasterNode = Depth == 0x00;
			// The next 4 bytes are the parent node's fingerprint
			ParentFingerprint = GetHostUInt32FromNetworkBytes(deserialisedKey[5..9]);
			// A master node doesn't have a parent, check parent fingerprint is all zeros
			if (IsMasterNode && ParentFingerprint == 0)
			{
				ParentFingerprint = null;
			}
			else if (IsMasterNode)
			{
				Clear();
				throw new ArgumentException("Depth value of 0 is incompatible with a non-zero parent fingerprint.", nameof(serialisedKey));
			}
			// The next 4 bytes is the child number
			ChildNumber = GetHostUInt32FromNetworkBytes(deserialisedKey[9..13]);
			// A serialised master node always has child index 0, but is not a child
			if (IsMasterNode && ChildNumber == 0)
			{
				ChildNumber = null;
			}
			else if (IsMasterNode)
			{
				Clear();
				throw new ArgumentException("Depth value of 0 is incompatible with an index value of zero.", nameof(serialisedKey));
			}
			// If depth is 0 (master node) or 1 (child of master node), we know the derivation path
			if (Depth <= 1)
			{
				DerivationPath = Depth == 0 ? "m" : string.Format(CultureInfo.InvariantCulture, "m/{0}", ChildNumberString);
			}
			// If we've been passed the derivation path, use it
			else if (nodeDerivationPath is not null)
			{
				DerivationPath = nodeDerivationPath;
			}
			// If depth is more than 1, indicate part of the derivation path is unknown
			else
			{
				string unknownPathString = "/???";
				int unknownPathRepeatCount = Depth - 1;
				string unknownPathRepeatedString = new StringBuilder(unknownPathString.Length * unknownPathRepeatCount).Insert(0, unknownPathString, unknownPathRepeatCount).ToString();
				DerivationPath = Depth == 0 ? "m" : string.Format(CultureInfo.InvariantCulture, "m/{0}/{1}", unknownPathRepeatedString, ChildNumberString);
			}
			// There are always 64 bytes for a node
			NodeBytes = new byte[64];
			// Copy the chain code to the right half of the node's bytes
			Array.Copy(deserialisedKey[13..45], 0, NodeBytes, 32, 32);
			// The next 33 bytes are the collapsed key
			byte[] collapsedKey = deserialisedKey[45..78];
			// If the collapsed key's prefix is 0x00, the collapsed key is a private key
			if (collapsedKey[0] == 0x00)
			{
				// We can determine the version bytes are for a private key
				VersionPrefixPrivate = versionPrefix;
				// Try to get the public version bytes from a lookup table
				VersionPrefixPublic = (uint?)(GetPublicVersionPrefix(GetPrivateVersionPrefix(versionPrefix)) ?? throw new ArgumentException("Lookup for private->public BIP-0032 version bytes failed. Does serialised key have conflicting values?", nameof(serialisedKey)));
				// Copy the uncollapsed private key to the left half of the node's bytes
				Array.Copy(deserialisedKey[46..78], 0, NodeBytes, 0, 32);
				// Create the private key
				PrivateKey = CalculateECPrivateKey(domainParams, [.. Left]);
				// Create the public key
				PublicKey = CalculateECPublicKey(domainParams, PrivateKey);
				bool serialisePrivSuccess = TryCalculateSerialisedPrivateKey(PrivateKey, out string? privKeySerialised);
				bool serialisePubSuccess = TryCalculateSerialisedPublicKey(PublicKey, out string? keyIdentifier, out string? pubKeySerialised);

				if (serialisePrivSuccess && serialisePubSuccess)
				{
					KeyIdentifier = keyIdentifier;
					Fingerprint = KeyIdentifier is null ? null : BitConverter.ToUInt32(Utils.ByteEncoding.FromNetworkByteOrderHexString(KeyIdentifier[..8]));
					PrivateKeySerialised = privKeySerialised;
					PublicKeySerialised = pubKeySerialised;
				}
				else
				{
					Clear();
					throw new CryptographicException("An error occured whilst serialising keys.");
				}
			}
			// If the prefix is 0x02 or 0x03, it is a public key, otherwise interpreting it isn't implemented
			else
			{
				bool qyIsEven = collapsedKey[0] == 0x02;
				bool qyIsOdd = collapsedKey[0] == 0x03;
				// If an unimplemented prefix, initialise the required variables and return
				if (!qyIsEven && !qyIsOdd)
				{
					Clear();
					VersionPrefixPublic = null;
					VersionPrefixPrivate = null;
					throw new ArgumentException("Unrecognised compressed key prefix.");
				}
				else
				{
					// We can determine the version bytes are for a public key
					VersionPrefixPublic = versionPrefix;
					// The version bytes for the private key would need a lookup table
					VersionPrefixPrivate = (uint?)GetPrivateVersionPrefix(GetPublicVersionPrefix(versionPrefix)) ?? throw new ArgumentException("Lookup for public->private BIP-0032 version bytes failed. Does serialised key have conflicting values?", nameof(serialisedKey));
					// Create the public key
					Org.BouncyCastle.Math.EC.ECPoint q = domainParams.Curve.DecodePoint(collapsedKey).Normalize();
					PublicKey = new(q, domainParams);
					bool serialisePubSuccess = TryCalculateSerialisedPublicKey(PublicKey, out string? keyIdentifier, out string? pubKeySerialised);

					if (serialisePubSuccess)
					{
						KeyIdentifier = keyIdentifier;
						Fingerprint = KeyIdentifier is null ? null : BitConverter.ToUInt32(Utils.ByteEncoding.FromNetworkByteOrderHexString(KeyIdentifier[..8]));
						PublicKeySerialised = pubKeySerialised;
					}
					else
					{
						throw new CryptographicException("An error occured whilst serialising key.");
					}
				}
			}
			IsInitialised = true;
		}

		/// <summary>
		/// Derive a child <see cref="Bip32Node"/> from <paramref name="parentNode"/> using index number <paramref name="childNumber"/>.
		/// </summary>
		/// <param name="domainParams">The domain parameters of the curve.</param>
		/// <param name="parentNode">The parent node.</param>
		/// <param name="childNumber">The <paramref name="parentNode"/>'s index number for this child node.</param>
		/// <returns>The child <see cref="Bip32Node"/>.</returns>
		public static Bip32Node? GetChildNode(ECDomainParameters domainParams, ref Bip32Node parentNode, uint childNumber)
		{
			ArgumentNullException.ThrowIfNull(parentNode);
			// Check that the parent node has been initialised and has a private key and chain code
			if (!parentNode.IsInitialised || parentNode.Left.SequenceEqual(Bip32Utils.Zeroed32ByteArray) || parentNode.Right.SequenceEqual(Bip32Utils.Zeroed32ByteArray) || parentNode.PrivateKey is null || parentNode.PublicKey is null)
			{
				return default;
			}
			byte[] nodeBytes = new byte[HMACSHA512.HashSizeInBytes];
			List<byte> data = [];
			byte[] hashResult;
			bool useHardenedDerivation = childNumber >= 0x8000_0000;
			// Hardened = HMACSHA512(parent chain code, 0x00 || parent private key || index)
			if (useHardenedDerivation)
			{
				data.Add(0x00);
				data.AddRange(parentNode.Left);
				data.AddRange(GetNetworkBytesFromHostUInt32(childNumber));
				hashResult = HMACSHA512.HashData([.. parentNode.Right], [.. data]);
			}
			// Normal = HMACSHA512(parent chain code, parent public key || index)
			else
			{
				data.AddRange(GetCompressedKey(parentNode.PublicKey));
				data.AddRange(GetNetworkBytesFromHostUInt32(childNumber));
				hashResult = HMACSHA512.HashData([.. parentNode.Right], [.. data]);
			}
			// The child's private key is the left side + parent private key (mod n)
			BigInteger privateKey = parentNode.PrivateKey.D.Add(new(1, hashResult[..32])).Mod(parentNode.PrivateKey.Parameters.N);
			byte[] privateKeyBytes = privateKey.ToByteArrayUnsigned() ?? new byte[32];
			Array.Copy(privateKeyBytes, 0, nodeBytes, 32 - privateKeyBytes.Length, privateKeyBytes.Length);
			// The right side of the hash output is the child node's chain key
			Array.Copy(hashResult, 32, nodeBytes, 32, 32);

			return new Bip32Node(nodeBytes, domainParams, parentNode.VersionPrefixPublic, parentNode.VersionPrefixPrivate, parentNode.DerivationPath, parentNode.Depth, parentNode.Fingerprint, childNumber);
		}

		/// <summary>
		/// Tries to calculate a serialised private key from a private key's parameters.
		/// </summary>
		/// <param name="privateKey">The parameters of a private key.</param>
		/// <param name="serialisedPrivateKey">The serialised private key on success; otherwise, <see langword="null"/>.</param>
		/// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
		private bool TryCalculateSerialisedPrivateKey(ECPrivateKeyParameters privateKey, [NotNullWhen(true)] out string? serialisedPrivateKey)
		{
			bool success = TryCalculateSerialisedKey(privateKey, out serialisedPrivateKey, out _);

			// We return true if the out variables are not null
			return success && serialisedPrivateKey is not null;
		}

		/// <summary>
		/// Tries to calculate a serialised public key and public key identifer from a public key's parameters.
		/// </summary>
		/// <param name="publicKey">The parameters of a public key.</param>
		/// <param name="keyIdentifier">The public key identifier on success; otherwise, <see langword="null"/>.</param>
		/// <param name="serialisedPublicKey">The serialised public key on success; otherwise, <see langword="null"/>.</param>
		/// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
		private bool TryCalculateSerialisedPublicKey(ECPublicKeyParameters publicKey, [NotNullWhen(true)] out string? keyIdentifier, [NotNullWhen(true)] out string? serialisedPublicKey)
		{
			bool success = TryCalculateSerialisedKey(publicKey, out serialisedPublicKey, out keyIdentifier);

			// We return true if the out variables are not null
			return success && keyIdentifier is not null && serialisedPublicKey is not null;
		}

		/// <summary>
		/// Tries to calculate a serialised private/public key and public key identifier from a private/public key's parameters.
		/// </summary>
		/// <param name="key">The parameters of a private key or public key.</param>
		/// <param name="serialisedKeyString">The serialised private/public key on success; otherwise, <see langword="null"/>.</param>
		/// <param name="keyIdentifier">The public key identifier on success; otherwise, <see langword="null"/>.</param>
		/// <returns><see langword="true"/> on success; otherwise, <see langword="false"/>.</returns>
		/// <exception cref="UnreachableException">Thrown if unreachable code is reached.</exception>
		private bool TryCalculateSerialisedKey(ECKeyParameters key, [NotNullWhen(true)] out string? serialisedKeyString, out string? keyIdentifier)
		{
			// Cast key to private key type if possible
			ECPrivateKeyParameters? privateKey = key as ECPrivateKeyParameters;
			// Cast key to public key type if possible
			ECPublicKeyParameters? publicKey = key as ECPublicKeyParameters;
			// Return early if key couldn't be cast as public/private key
			if (privateKey is null && publicKey is null)
			{
				serialisedKeyString = null;
				keyIdentifier = null;
				return false;
			}

			// Create a byte list for the serialised private key
			List<byte> serialisedKeyList = [];

			// Add byte[4] version bytes, network byte order
			uint versionPrefixPrivate = VersionPrefixPrivate is not null ? (uint)VersionPrefixPrivate : 0;
			uint versionPrefixPublic = VersionPrefixPublic is not null ? (uint)VersionPrefixPublic : 0;
			byte[]? versionBytes = privateKey is not null ? GetNetworkBytesFromHostUInt32(versionPrefixPrivate) : GetNetworkBytesFromHostUInt32(versionPrefixPublic);
			serialisedKeyList.AddRange([.. versionBytes]);
			// Add byte[1] node depth, master node being 0x00
			serialisedKeyList.Add(Depth);
			// Add byte[4] parent fingerprint, network byte order
			uint parentFingerprint = ParentFingerprint is not null ? (uint)ParentFingerprint : 0;
			serialisedKeyList.AddRange(GetNetworkBytesFromHostUInt32(parentFingerprint));
			// Add byte[4] child number for current node, network byte order
			uint childNumber = ChildNumber is not null ? (uint)ChildNumber : 0;
			serialisedKeyList.AddRange(GetNetworkBytesFromHostUInt32(childNumber));
			// Add byte[32] chain code (current node), network byte order
			serialisedKeyList.AddRange(Right);
			// Lastly, Add byte[33] compressed key...

			// If a private key, append the compressed key
			if (privateKey is not null)
			{
				// Calculate and append the compressed key to the serialised key
				serialisedKeyList.AddRange(GetCompressedKey(privateKey));
				// Key identifier requires public key
				keyIdentifier = null;
			}
			// If a public key, append the compressed key and calculate the key identifier
			else if (publicKey is not null)
			{
				// Calculate the compressed key
				byte[] compressedPublicKey = GetCompressedKey(publicKey);
				// Append the compressed key to the serialised key
				serialisedKeyList.AddRange(compressedPublicKey);
				// Calculate the key identifier
				keyIdentifier = CalculateKeyIdentifier([.. compressedPublicKey]);
			}
			else
			{
				throw new UnreachableException();
			}

			// The serialised key can now be encoded using Base58Check
			byte[] zeroLengthByteArray = [];
			_ = ByteEncoding.TryGetToBase58CheckEncoded(zeroLengthByteArray, [.. serialisedKeyList], out byte[]? serialisedKeyBytes);
			serialisedKeyString = ByteEncoding.GetBase58StringFromRawBase58(serialisedKeyBytes);

			// We return true if the out variables are not null
			return serialisedKeyString is not null;
		}

		/// <summary>
		/// Clear/Zero the internal 64-byte <see cref="byte"/>[] array for this <see cref="Bip32Node"/>.
		/// </summary>
		/// <remarks>
		/// <para>Also clears/zeros <see cref="Left"/> and <see cref="Right"/> as they are <see cref="ReadOnlySpan{T}"/>'s of the internal <see cref="byte"/>[] array.</para>
		/// <para>Note: Does not clear other calculated values, such as serialised keys.</para>
		/// </remarks>
		public void Clear()
		{
			if (NodeBytes is not null)
			{
				Array.Clear(NodeBytes, 0, NodeBytes.Length);
			}
		}
	}
}
