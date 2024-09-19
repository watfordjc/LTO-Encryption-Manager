using System;
using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	public static partial class StandardRSA
	{
		/// <summary>
		/// Creates a big endian unsigned byte array of a required byte length by padding with leading zeros.
		/// </summary>
		/// <param name="bigInteger">The number to convert into a byte array.</param>
		/// <param name="requiredByteLength">The required length of the byte array.</param>
		/// <returns>A big endian unsigned byte array of the required byte length.</returns>
		public static byte[] PadBigEndianArrayWithLeadingZeros(BigInteger bigInteger, int requiredByteLength)
		{
			// If no leading 0x00 bytes are needed, just use BigInteger.ToByteArray()
			if (bigInteger.GetByteCount(true) == requiredByteLength)
			{
				// Return the BigInteger as a big endian unsigned byte array
				return bigInteger.ToByteArray(true, true);
			}
			// Otherwise, create a big endian byte array with leading zeros
			else
			{
				// Create a byte array of the required length
				byte[] bigEndianBytes = new byte[requiredByteLength];
				// Store the BigInteger as a big endian unsigned byte array
				byte[] bigIntegerBigEndianBytes = bigInteger.ToByteArray(true, true);
				// Calculate the number of leading zeros needed
				int offset = bigEndianBytes.Length - bigIntegerBigEndianBytes.Length;
				// Copy the BigInteger big endian array into the byte array after the required number of leading zeros
				Array.Copy(bigIntegerBigEndianBytes, 0, bigEndianBytes, offset, bigIntegerBigEndianBytes.Length);
				// Return the byte array
				return bigEndianBytes;
			}
		}
	}
}
