using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
	public static partial class Encodings
	{
		/// <summary>
		/// An array of 256 strings containing the hex digit values (as strings) for the byte values 0x00 through 0xFF.
		/// </summary>
		private static readonly string[] hexadecimalByteDictionary = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F", "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF", "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"];
		/// <summary>
		/// An array of 256 bytes containing the numerical values (as bytes) for the ASCII positions of the hex digits 0-9, A-F, a-f. Invalid positions contain the byte value 255.
		/// </summary>
		private static readonly byte[] hexadecimalCharDictionary = [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255];

		/// <summary>
		/// Converts a byte array (host byte order) into a hexadecimal string (network byte order).
		/// </summary>
		/// <param name="bytes">A byte array in host byte order.</param>
		/// <returns>A hexadecimal string in network byte order.</returns>
		public static string ToNetworkByteOrderHexString(ReadOnlySpan<byte> bytes)
		{
			// If the byte array is empty, return an empty string
			if (bytes.IsEmpty)
			{
				return string.Empty;
			}

			if (BitConverter.IsLittleEndian)
			{
				// Use a StringBuilder to build the hexadecimal string
				StringBuilder sb = new(bytes.Length * 2);
				// For little endian systems, we need to reverse the byte order
				for (int i = bytes.Length - 1; i >= 0; i--)
				{
					// Convert the current byte to two hex digits
					sb.Append(hexadecimalByteDictionary[bytes[i]]);
				}
				return sb.ToString();
			}
			else
			{
				// For big endian systems, we keep the existing byte order
				return ToHexString(bytes);
			}
		}

		/// <summary>
		/// Converts a byte array to a hex string without changing byte order.
		/// </summary>
		/// <param name="bytes">A byte array.</param>
		/// <returns>A hexadecimal string.</returns>
		public static string ToHexString(ReadOnlySpan<byte> bytes)
		{
			// If the byte array is empty, return an empty string
			if (bytes.IsEmpty)
			{
				return string.Empty;
			}

			// Use a StringBuilder to build the hexadecimal string
			StringBuilder sb = new(bytes.Length * 2);
			// Keep the existing byte order
			for (int i = 0; i < bytes.Length; i++)
			{
				// Convert the current byte to two hex digits
				sb.Append(hexadecimalByteDictionary[bytes[i]]);
			}
			// Return the hex string
			return sb.ToString();
		}

		/// <summary>
		/// Converts a hexadecimal string (network byte order) to a byte array (host byte order).
		/// </summary>
		/// <param name="hexString">A hexadecimal string in network byte order.</param>
		/// <returns>A byte array in host byte order.</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="hexString"/> does not have an even number of hex digits.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="hexString"/> contains an invalid ASCII hex digit.</exception>
		public static byte[] FromNetworkByteOrderHexString(string? hexString)
		{
			// If the string is null or empty, return an empty byte array
			if (string.IsNullOrEmpty(hexString))
			{
				return [];
			}
			// Check there are an even number of hex digits
			else if (hexString.Length % 2 != 0)
			{
				ThrowInvalidHexStringLength(nameof(hexString), hexString.Length);
			}

			if (BitConverter.IsLittleEndian)
			{
				// A byte array to hold the return value
				byte[] bytes = new byte[hexString.Length / 2];
				// A variable to store the upper (most significant) digit's value
				byte upperDigit;
				// A variable to store the lower (least significant) digit's value
				byte lowerDigit;
				// We want to start at the last two digits and work towards index 0 and 1
				for (int bytePos = 0, i = hexString.Length - 2, j = hexString.Length - 1; i >= 0; bytePos++, i -= 2, j -= 2)
				{
					// Get the numerical ASCII code point of the upper digit
					upperDigit = hexadecimalCharDictionary[hexString[i]];
					// Get the numerical ASCII code point of the lower digit
					lowerDigit = hexadecimalCharDictionary[hexString[j]];
					// Check the first hex digit is an ASCII hex digit
					if (upperDigit == 255)
					{
						ThrowInvalidHexDigit(nameof(hexString), hexString[i], i);
					}
					// Check the second hex digit is an ASCII hex digit
					else if (lowerDigit == 255)
					{
						ThrowInvalidHexDigit(nameof(hexString), hexString[j], j);
					}
					else
					{
						// Set the byte value (the first digit left-shifted by 4 bits ORed with the lower 4 bits of the second digit)
						bytes[bytePos] = (byte)((upperDigit << 4) | (lowerDigit & 0xF));
					}
				}
				// Return the byte[] value
				return bytes;
			}
			else
			{
				// For big endian systems, we keep the existing byte order
				return FromHexString(hexString);
			}
		}

		/// <summary>
		/// Converts a hex string to a byte array without changing byte order.
		/// </summary>
		/// <param name="hexString">A hexadecimal string.</param>
		/// <returns>A byte array.</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="hexString"/> does not have an even number of hex digits.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="hexString"/> contains an invalid ASCII hex digit.</exception>
		public static byte[] FromHexString(string? hexString)
		{
			// If the string is null or empty, return an empty byte array
			if (string.IsNullOrEmpty(hexString))
			{
				return [];
			}
			// Check there are an even number of hex digits
			else if (hexString.Length % 2 != 0)
			{
				ThrowInvalidHexStringLength(nameof(hexString), hexString.Length);
			}

			// A byte array to hold the return value
			byte[] bytes = new byte[hexString.Length / 2];
			// A variable to store the upper (most significant) digit's value
			byte upperDigit;
			// A variable to store the lower (least significant) digit's value
			byte lowerDigit;
			// Keep the existing byte order
			for (int bytePos = 0, i = 0, j = 1; i < hexString.Length; bytePos++, i += 2, j += 2)
			{
				upperDigit = hexadecimalCharDictionary[hexString[i]];
				lowerDigit = hexadecimalCharDictionary[hexString[j]];
				// Check the first hex digit is an ASCII hex digit
				if (upperDigit == 255)
				{
					ThrowInvalidHexDigit(nameof(hexString), hexString[i], i);
				}
				// Check the second hex digit is an ASCII hex digit
				else if (lowerDigit == 255)
				{
					ThrowInvalidHexDigit(nameof(hexString), hexString[j], j);
				}
				else
				{
					// Set the byte value (the first digit left-shifted by 4 bits ORed with the lower 4 bits of the second digit)
					bytes[bytePos] = (byte)((upperDigit << 4) | (lowerDigit & 0xF));
				}
			}
			// Return the byte[] value
			return bytes;
		}

		[DoesNotReturn]
		private static void ThrowInvalidHexDigit(string paramName, char hexDigit, int hexStringIndex) =>
			throw new ArgumentOutOfRangeException(paramName, $"Invalid ASCII hexadecimal digit '{hexDigit}' (ASCII code point {(byte)hexDigit}) at index {hexStringIndex}.");
		[DoesNotReturn]
		private static void ThrowInvalidHexStringLength(string paramName, int paramValueLength) =>
			throw new ArgumentException($"Hexadecimal string must have an even number of digits, but it has {paramValueLength}.", paramName);
	}
}
