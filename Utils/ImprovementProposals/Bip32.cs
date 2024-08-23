using CryptHash.Net.Encoding;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals
{
	public static class Bip32
	{
		/// <summary>
		/// BIP-0032 version bytes for public keys.
		/// </summary>
		/// <remarks>
		/// <para>Note: The hex values are converted to host byte order (Little Endian on Windows) when they become <c>uint</c>.</para>
		/// </remarks>
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum Storage should be Int32", Justification = "BIP-0032 version prefixes are unsigned 32-bit integers")]
		public enum PublicKeyVersionPrefix : uint
		{
			None = 0x0000_0000,						// "1111"
			BitcoinMainnetPublic = 0x0488_b21e,		// "xpub"
			BitcoinTestnetPublic = 0x0435_87cf		// "tpub"
		}

		/// <summary>
		/// BIP-0032 version bytes for private keys.
		/// </summary>
		/// <remarks>
		/// <para>Note: The hex values are converted to host byte order (Little Endian on Windows) when they become <c>uint</c>.</para>
		/// </remarks>
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1028:Enum Storage should be Int32", Justification = "BIP-0032 version prefixes are unsigned 32-bit integers")]
		public enum PrivateKeyVersionPrefix : uint
		{
			None = 0x0000_0000,                     // "1111"
			BitcoinMainnetPrivate = 0x0488_ade4,	// "xprv"
			BitcoinTestnetPrivate = 0x0042_80fa		// "tprv"
		}

		/// <summary>
		/// Gets the equivalent <see  cref="PublicKeyVersionPrefix"/> for a given <see  cref="PrivateKeyVersionPrefix"/>.
		/// </summary>
		/// <param name="privateVersionPrefix">The version prefix for a private key.</param>
		/// <returns>The equivalent public key version prefix.</returns>
		public static PublicKeyVersionPrefix? GetPublicVersionPrefix(PrivateKeyVersionPrefix? privateVersionPrefix)
		{
			return privateVersionPrefix switch
			{
				PrivateKeyVersionPrefix.BitcoinMainnetPrivate => PublicKeyVersionPrefix.BitcoinMainnetPublic,
				PrivateKeyVersionPrefix.BitcoinTestnetPrivate => PublicKeyVersionPrefix.BitcoinTestnetPublic,
				_ => null
			};
		}

		/// <summary>
		/// Gets the equivalent <see  cref="PrivateKeyVersionPrefix"/> for a given <see  cref="PublicKeyVersionPrefix"/>.
		/// </summary>
		/// <param name="publicVersionPrefix">The version prefix for a public key.</param>
		/// <returns>The equivalent private key version prefix.</returns>
		public static PrivateKeyVersionPrefix? GetPrivateVersionPrefix(PublicKeyVersionPrefix? publicVersionPrefix)
		{
			return publicVersionPrefix switch
			{
				PublicKeyVersionPrefix.BitcoinMainnetPublic => PrivateKeyVersionPrefix.BitcoinMainnetPrivate,
				PublicKeyVersionPrefix.BitcoinTestnetPublic => PrivateKeyVersionPrefix.BitcoinTestnetPrivate,
				_ => null
			};
		}

		public static uint GetHostUInt32FromNetworkBytes(byte[] networkBytes)
		{
			if (!BitConverter.IsLittleEndian)
			{
				return BitConverter.ToUInt32(networkBytes);
			}
			else
			{
				byte[] networkBytesBigEndian = networkBytes;
				Array.Reverse(networkBytesBigEndian);
				return BitConverter.ToUInt32(networkBytesBigEndian);
			}
		}

		public static byte[] GetNetworkBytesFromHostUInt32(uint hostUInt32)
		{
			if (!BitConverter.IsLittleEndian)
			{
				return BitConverter.GetBytes(hostUInt32);
			}
			else
			{
				byte[] networkBytesBigEndian = BitConverter.GetBytes(hostUInt32);
				Array.Reverse(networkBytesBigEndian);
				return networkBytesBigEndian;
			}
		}

		/// <summary>
		/// Gets the <see cref="PrivateKeyVersionPrefix"/> for a given BIP-0032 private key prefix.
		/// </summary>
		/// <param name="versionPrefix">A BIP-0032 private key prefix.</param>
		/// <returns><see cref="PrivateKeyVersionPrefix"/>, or <c>null</c>.</returns>
		public static PrivateKeyVersionPrefix? GetPrivateVersionPrefix(uint versionPrefix)
		{
			if (Enum.IsDefined(typeof(PrivateKeyVersionPrefix), versionPrefix))
			{
				return (PrivateKeyVersionPrefix)versionPrefix;
			}
			else
			{
				return null;
			}
		}

		/// <summary>
		/// Gets the <see cref="PublicKeyVersionPrefix"/> for a given BIP-0032 public key prefix.
		/// </summary>
		/// <param name="versionPrefix">A BIP-0032 public key prefix.</param>
		/// <returns><see cref="PublicKeyVersionPrefix"/>, or <c>null</c>.</returns>
		public static PublicKeyVersionPrefix? GetPublicVersionPrefix(uint versionPrefix)
		{
			if (Enum.IsDefined(typeof(PublicKeyVersionPrefix), versionPrefix))
			{
				return (PublicKeyVersionPrefix)versionPrefix;
			}
			else
			{
				return null;
			}
		}

		/// <summary>
		/// Gets the <see cref="Type"/> for a given BIP-0032 public/private key prefix.
		/// </summary>
		/// <param name="versionPrefix">A BIP-0032 public/private key prefix.</param>
		/// <returns><see cref="PrivateKeyVersionPrefix"/>, <see cref="PublicKeyVersionPrefix"/>, or <c>null</c>.</returns>
		public static Type? GetVersionPrefixType(uint? versionPrefix)
		{
			if (versionPrefix is null)
			{
				return null;
			}
			else if (Enum.IsDefined(typeof(PrivateKeyVersionPrefix), versionPrefix))
			{
				return typeof(PrivateKeyVersionPrefix);
			}
			else if (Enum.IsDefined(typeof(PublicKeyVersionPrefix), versionPrefix))
			{
				return typeof(PublicKeyVersionPrefix);
			}
			else
			{
				return null;
			}
		}

		/// <summary>
		/// Gets a curve name for a given <see  cref="PrivateKeyVersionPrefix"/>.
		/// </summary>
		/// <param name="versionPrefix">A BIP-0032 version prefix for private keys.</param>
		/// <returns>The curve's well-known name, or <c>null</c> if not found.</returns>
		public static string? GetCurveName(PrivateKeyVersionPrefix? versionPrefix)
		{
			return versionPrefix switch
			{
				PrivateKeyVersionPrefix.BitcoinMainnetPrivate => "secp256k1",
				PrivateKeyVersionPrefix.BitcoinTestnetPrivate => "secp256k1",
				_ => null
			};
		}

		/// <summary>
		/// Gets a curve name for a given <see  cref="PublicKeyVersionPrefix"/>.
		/// </summary>
		/// <param name="versionPrefix">A BIP-0032 version prefix for public keys.</param>
		/// <returns>The curve's well-known name, or <c>null</c> if not found.</returns>
		public static string? GetCurveName(PublicKeyVersionPrefix? versionPrefix)
		{
			return versionPrefix switch
			{
				PublicKeyVersionPrefix.BitcoinMainnetPublic => "secp256k1",
				PublicKeyVersionPrefix.BitcoinTestnetPublic => "secp256k1",
				_ => null
			};
		}

		/// <summary>
		/// Gets a curve name for a given BIP-0032 version prefix.
		/// </summary>
		/// <param name="versionPrefix">A BIP-0032 version prefix for public/private keys.</param>
		/// <returns>The curve's well-known name, or <c>null</c> if not found.</returns>
		public static string? GetCurveName(uint versionPrefix)
		{
			Type? type = GetVersionPrefixType(versionPrefix);
			if (type == typeof(PrivateKeyVersionPrefix))
			{
				PrivateKeyVersionPrefix? privateKeyVersionPrefix = GetPrivateVersionPrefix(versionPrefix);
				return GetCurveName(privateKeyVersionPrefix);
			}
			else if (type == typeof(PublicKeyVersionPrefix))
			{
				PublicKeyVersionPrefix? publicKeyVersionPrefix = GetPublicVersionPrefix(versionPrefix);
				return GetCurveName(publicKeyVersionPrefix);
			}
			else
			{
				return null;
			}
		}

		/// <summary>
		/// Gets the elliptic curve domain parameters for a known curve.
		/// </summary>
		/// <param name="versionPrefix">A BIP-0032 version prefix for public/private keys.</param>
		/// <returns>The curve's domain parameters.</returns>
		public static ECDomainParameters? GetDomainParameters(uint versionPrefix)
		{
			string? curveName = GetCurveName(versionPrefix);
			if (curveName == null)
			{
				return default;
			}

			// Get the parameters of the curve and fail if curve is unknown
			X9ECParameters? curveParams = ECNamedCurveTable.GetByName(curveName);
			if (curveParams == null)
			{
				return default;
			}

			// Return the parameters of the domain
			return new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H, curveParams.GetSeed());
		}


		public static ECPrivateKeyParameters CalculateECPrivateKey(ECDomainParameters domainParams, byte[] rawPrivateKey)
		{
			ArgumentNullException.ThrowIfNull(domainParams);
			// The master key is the left half of the hash, convert for sanity checks
			BigInteger d = new(1, rawPrivateKey);
			if (d.CompareTo(BigInteger.Zero) == 0)
			{
				throw new ArgumentOutOfRangeException(nameof(rawPrivateKey), "Private key is 0.");
			}
			else if (d.CompareTo(domainParams.N) >= 0)
			{
				throw new ArgumentOutOfRangeException(nameof(rawPrivateKey), "Private key is not less than n.");
			}
			// Create/calculate the private key
			return new(d, new(domainParams.Curve, domainParams.G, domainParams.N, domainParams.H, domainParams.GetSeed()));
		}

		public static ECPublicKeyParameters CalculateECPublicKey(ECDomainParameters domainParams, ECPrivateKeyParameters privateKey)
		{
			ArgumentNullException.ThrowIfNull(privateKey);
			// Calculate q
			Org.BouncyCastle.Math.EC.ECPoint q = privateKey.Parameters.G.Multiply(privateKey.D);
			// Normalise q to ensure Z equals 1 - math optimisations might create an intermediate point (x, y, z) but we want (x, y)
			q.Normalize();
			// Create/calculate the public key
			return new(privateKey.AlgorithmName, q, domainParams);
		}

		public static byte[] GetCompressedKey(ECPrivateKeyParameters keyParams)
		{
			ArgumentNullException.ThrowIfNull(keyParams);
			// For a private key, compression is (0x00 || serialise_256b(k)), or 0x00 followed by the private key in network byte order
			byte[] compressedKey = new byte[33];
			compressedKey[0] = 0x00;
			byte[] d = keyParams.D.ToByteArrayUnsigned();
			int leadingZeros = 32 - d.Length;
			Array.Copy(d, 0, compressedKey, 1 + leadingZeros, 32 - leadingZeros);
			return compressedKey;
		}

		public static byte[] GetCompressedKey(ECPublicKeyParameters keyParams)
		{
			ArgumentNullException.ThrowIfNull(keyParams);
			// For a public key, SEC1 compression is (serialize_point(K)), where K is the public key's (x, y) point
			// SEC1 compression of (x, y) is 33 bytes: a leading byte to indicate if y is even (0x02) or odd (0x03), and the 32 x bytes in network byte order
			byte[] compressedKey = new byte[33];

			// Convert y to a BigInteger for some maths
			BigInteger qyNum = keyParams.Q.AffineYCoord.ToBigInteger();
			// Append 0x02 if y is even, 0x03 if y is odd
			compressedKey[0] = (byte)(qyNum.Mod(BigInteger.Two) == BigInteger.Zero ? 0x02 : 0x03);
			// Append x
			Array.Copy(keyParams.Q.AffineXCoord.GetEncoded(), 0, compressedKey, 1, 32);
			return compressedKey;
		}

		public static string CalculateKeyIdentifier(byte[] compressedPublicKey)
		{
			// The key identifier for this node is RIPEMD160(SHA256(serialize_point(K)))
			RipeMD160Digest ripeMD160 = new();
			// 160 bits is 20 bytes
			byte[] tempKeyIdentifier = new byte[20];
			// Pass SHA2-256(serialize_point(K)) to RIPEMD160
			ripeMD160.BlockUpdate(SHA256.HashData(compressedPublicKey.ToArray()), 0, SHA256.HashSizeInBytes);
			// Calculate the RIPEMD160 digest
			ripeMD160.DoFinal(tempKeyIdentifier, 0);
			// Return the key identifier
			return Hexadecimal.ToHexString(tempKeyIdentifier).ToUpperInvariant();
		}

		/// <summary>
		/// Derive a BIP-0032 master node (m) from a binary master secret.
		/// </summary>
		/// <param name="seedBytes">The binary master secret (e.g. a BIP-0039 binary seed).</param>
		/// <param name="versionPrefixPublic">The prefix for public keys.</param>
		/// <param name="versionPrefixPrivate">The prefix for private keys.</param>
		/// <param name="curveName">The string representation of the curve name (e.g. secp256k1).</param>
		/// <returns>A master <see  cref="Bip32Node"/> (m).</returns>
		public static Bip32Node? GetMasterNodeFromBinarySeed(in ReadOnlySpan<byte> seedBytes, uint? versionPrefixPublic, uint? versionPrefixPrivate, string curveName = "secp256k1")
		{
			// Convert the curveName to a BIP-0032/SLIP-0010 HMAC key, and fail if curveName is invalid/unknown
			string? curveString = curveName switch
			{
				"secp256k1" => "Bitcoin seed",
				"secp256r1" => "Nist256p1 seed",
				"ed25519" => "ed25519 seed",
				_ => null
			};
			if (curveString == null)
			{
				return default;
			}

			// Get the parameters of the curve and fail if curve is unknown
			X9ECParameters? curveParams = ECNamedCurveTable.GetByName(curveName);
			if (curveParams == null)
			{
				return default;
			}

			// Get the parameters of the domain
			ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H, curveParams.GetSeed());

			// BIP-0032/SLIP-0010 defines the key for the master node and HMAC-SHA512 as algorithm
			byte[] hmacKey = Encoding.UTF8.GetBytes(curveString);
			using HMACSHA512 hmac = new(hmacKey);
			// Compute the hash
			byte[] hashResult = hmac.ComputeHash(seedBytes.ToArray());

			// The master key is the left half of the hash, convert for sanity checks
			BigInteger d = new(1, hashResult[..32]);
			// BIP-0032: for curve secp256k1, if left == 0 or >= n, the master key is invalid
			if (curveName == "secp256k1" && (d.CompareTo(BigInteger.Zero) == 0 || d.CompareTo(domainParams.N) >= 0))
			{
				return default;
			}
			// SLIP-0010: for curves not ed25519, rehash if left == 0 or >= n
			if (curveName != "ed25519")
			{
				while (d.CompareTo(BigInteger.Zero) == 0 || d.CompareTo(domainParams.N) >= 0)
				{
					hashResult = hmac.ComputeHash(hashResult[..32]);
					d = new(1, hashResult[..32]);
				}
			}
			hmac.Clear();

			return new(hashResult, domainParams, versionPrefixPublic, versionPrefixPrivate, null, null, null, null);
		}

		/// <summary>
		/// Derive a BIP-0032 master node (m) from a serialised private key.
		/// </summary>
		/// <param name="serialisedPrivateKey">A serialised private key.</param>
		/// <returns>A master <see  cref="Bip32Node"/> (m).</returns>
		public static Bip32Node GetMasterNodeFromSerialisedPrivateKey(in string serialisedPrivateKey)
		{
			return new(serialisedPrivateKey);
		}
	}
}
