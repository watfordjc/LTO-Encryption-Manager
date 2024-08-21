using Org.BouncyCastle.Asn1.X509.Qualified;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Controls;
using System.Windows.Documents;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;
using static uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Bip32;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals
{
	public static class Bip32
	{
		public enum PublicKeyVersionPrefix : uint
		{
			PublicVersionPrefix_xpub = 0x0488_b21e,
			PublicVersionPrefix_tpub = 0x0435_87cf
		}

		public enum PrivateKeyVersionPrefix : uint
		{
			PrivateVersionPrefix_xprv = 0x0488_ade4,
			PrivateVersionPrefix_tprv = 0x0042_80fa
		}

		public static PublicKeyVersionPrefix? GetPublicVersionPrefix(PrivateKeyVersionPrefix? privateVersionPrefix)
		{
			return privateVersionPrefix switch
			{
				PrivateKeyVersionPrefix.PrivateVersionPrefix_xprv => PublicKeyVersionPrefix.PublicVersionPrefix_xpub,
				PrivateKeyVersionPrefix.PrivateVersionPrefix_tprv => PublicKeyVersionPrefix.PublicVersionPrefix_tpub,
				_ => null
			};
		}

		public static PrivateKeyVersionPrefix? GetPrivateVersionPrefix(PublicKeyVersionPrefix? publicVersionPrefix)
		{
			return publicVersionPrefix switch
			{
				PublicKeyVersionPrefix.PublicVersionPrefix_xpub => PrivateKeyVersionPrefix.PrivateVersionPrefix_xprv,
				PublicKeyVersionPrefix.PublicVersionPrefix_tpub => PrivateKeyVersionPrefix.PrivateVersionPrefix_tprv,
				_ => null
			};
		}

		public static byte[] ReversePrefixBytes(byte[] versionPrefixOriginal)
		{
			if (BitConverter.IsLittleEndian)
			{
				byte[] versionPrefix = new byte[versionPrefixOriginal.Length];
				Array.Copy(versionPrefixOriginal, versionPrefix, versionPrefixOriginal.Length);
				Array.Reverse(versionPrefix);
				return versionPrefix;
			}
			else
			{
				return versionPrefixOriginal;
			}
		}

		public static byte[]? GetBigEndianBytes(PrivateKeyVersionPrefix? versionPrefix)
		{
			if (versionPrefix is null)
			{
				return null;
			}
			return GetBigEndianBytes((uint)(PrivateKeyVersionPrefix)versionPrefix);
		}

		public static byte[]? GetBigEndianBytes(PublicKeyVersionPrefix? versionPrefix)
		{
			if (versionPrefix is null)
			{
				return null;
			}
			return GetBigEndianBytes((uint)(PublicKeyVersionPrefix)versionPrefix);
		}

		public static byte[]? GetBigEndianBytes(uint? versionPrefix)
		{
			if (versionPrefix is null)
			{
				return null;
			}
			byte[] versionBytes = BitConverter.GetBytes((uint)versionPrefix);
			if (BitConverter.IsLittleEndian)
			{
				Array.Reverse(versionBytes);
			}
			return versionBytes;
		}

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

		public static string? GetCurveName(PrivateKeyVersionPrefix? versionPrefix)
		{
			return versionPrefix switch
			{
				PrivateKeyVersionPrefix.PrivateVersionPrefix_xprv => "secp256k1",
				PrivateKeyVersionPrefix.PrivateVersionPrefix_tprv => "secp256k1",
				_ => null
			};
		}

		public static string? GetCurveName(PublicKeyVersionPrefix? versionPrefix)
		{
			return versionPrefix switch
			{
				PublicKeyVersionPrefix.PublicVersionPrefix_xpub => "secp256k1",
				PublicKeyVersionPrefix.PublicVersionPrefix_tpub => "secp256k1",
				_ => null
			};
		}

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

		/// <summary>
		/// Derive a BIP-0032 master node (m) from a binary master secret.
		/// </summary>
		/// <param name="seedBytes">The binary master secret (e.g. a BIP-0039 binary seed).</param>
		/// <param name="curveName">The string representation of the curve name (e.g. secp256k1).</param>
		/// <returns>A BIP-0032 master <see cref="Slip0021Node"/> (m).</returns>
		public static Bip32Node GetMasterNodeFromBinarySeed(in ReadOnlySpan<byte> seedBytes, uint? versionBytesPublic, uint? versionBytesPrivate, string curveName = "secp256k1")
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
			if (curveString == "secp256k1" && (d.CompareTo(BigInteger.Zero) == 0 || d.CompareTo(domainParams.N) >= 0))
			{
				return default;
			}
			// SLIP-0010: for curves not ed25519, rehash if left == 0 or >= n
			if (curveString != "ed25519")
			{
				while (d.CompareTo(BigInteger.Zero) == 0 || d.CompareTo(domainParams.N) >= 0)
				{
					hashResult = hmac.ComputeHash(hashResult[..32]);
					d = new(1, hashResult[..32]);
				}
			}
			hmac.Clear();

			return new(hashResult, domainParams, versionBytesPublic, versionBytesPrivate, null, null, null, null);
		}

		public static Bip32Node GetMasterNodeFromSerialisedPrivateKey(in string serialisedPrivateKey)
		{
			return new(serialisedPrivateKey);
		}
	}
}
