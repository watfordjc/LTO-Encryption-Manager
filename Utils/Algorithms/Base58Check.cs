using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	public static class Base58Check
	{
		/// <summary>
		/// Tries to encode a version and some data into Base58Check-encoding. All inputs are base256.
		/// </summary>
		/// <param name="versionBytes">The Base58Check version bytes in base256 (should be an empty array for BIP-0032).</param>
		/// <param name="data">The data (base256) to encode as Base58Check.</param>
		/// <param name="versionedData">The Base58Check-encoded data (Base58 raw bytes).</param>
		/// <returns><code>true</code> on success.</returns>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="versionBytes"/> or <paramref name="data"/> is <code>null</code>.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="data"/> is an empty array.</exception>
		public static bool TryEncode(ReadOnlySpan<byte> versionBytes, ReadOnlySpan<byte> data, [NotNullWhen(true)] out byte[]? versionedData)
		{
			// Attempting to encode null is probably an error
			if (data == null || versionBytes == null)
			{
				throw new ArgumentNullException(nameof(data));
			}
			// Attempting to encode nothing is probably an error
			else if (data.Length == 0)
			{
				throw new ArgumentException("Argument is an empty array.", nameof(data));
			}
			// Create a List<byte> that can hold the version bytes, the data, and the checksum
			List<byte> checksummedData = new(versionBytes.Length + data.Length + 4);
			// Add the version bytes - BIP-0032 serialisation stores the version bytes elsewhere
			checksummedData.AddRange(versionBytes);
			// Add the data
			checksummedData.AddRange(data);
			// Add the checksum
			checksummedData.AddRange(GetChecksum([.. data]));

			return Base58.TryGetRawBase58FromBase256([.. checksummedData], out versionedData);
		}

		/// <summary>
		/// Gets the Base58Check checksum (first 4 bytes of double-SHA256) for given <paramref name="data"/>.
		/// </summary>
		/// <param name="data">The data to create a checksum of.</param>
		/// <returns>The 4-byte Base58Check checksum in base256.</returns>
		private static byte[] GetChecksum(byte[] data)
		{
			// Base58Check checksum is the first 4 bytes of the double SHA2-256 hash.
			return SHA256.HashData(SHA256.HashData(data))[..4];
		}

		/// <summary>
		/// Verifies Base58Check <paramref name="versionedData"/> against its included checksum.
		/// </summary>
		/// <param name="versionedData">A Base58Check string that has been decoded to base256.</param>
		/// <returns><code>true</code> if the checksum within <paramref name="versionedData"/> and the calculated checksum math.</returns>
		/// <exception cref="ArgumentNullException">Thrown if <paramref name="versionedData"/> is null.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="versionedData"/> is an empty array.</exception>
		public static bool VerifyChecksum(ReadOnlySpan<byte> versionedData)
		{
			// Attempting to verify null is probably an error
			if (versionedData == null)
			{
				throw new ArgumentNullException(nameof(versionedData));
			}
			// Attempting to verify an empty array is probably an error
			else if (versionedData.Length == 0)
			{
				throw new ArgumentException("Argument is an empty array.", nameof(versionedData));
			}
			// The data originally encoded (including for BIP-0032) is everything but the last 4 bytes
			ReadOnlySpan<byte> data = versionedData[..^4];
			// The original checksum is the last 4 bytes
			ReadOnlySpan<byte> checksum = versionedData[^4..];
			// Recalculate the checksum
			ReadOnlySpan<byte> calculatedChecksum = GetChecksum([.. data]);
			// Return true if the original checksum and the calculated checksum match
			return checksum.SequenceEqual(calculatedChecksum);
		}
	}
}
