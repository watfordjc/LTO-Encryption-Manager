/*
 * Based on code examples from Google Gemini (with necessary corrections):
 * Gemini: "The code I provided is based on my understanding of Base58 encoding principles and C# language syntax."
 * Gemini: "I believe the code falls under the category of public domain."
 */

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Text;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
    public static partial class Encodings
	{
        // Base58 digits, from [0] to [57]
        private const string base58EncoderAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        // byte values for UTF-8 Base58 digits - use sbyte[] so invalid values can be set to -1 (Base58 alphabet is ASCII, so values fit in range 0 through +127)
        private static readonly sbyte[] base58DecoderAlphabet = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1, -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1, -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1];
        // A static BigInteger = 58
        private static readonly BigInteger bigInt58 = new(58);
        // A static BigInteger = 256
        private static readonly BigInteger bigInt256 = new(256);
        /// <summary>
        /// Converts a ReadOnlySpan of bytes into an array of Base58 raw digit values.
        /// </summary>
        /// <param name="input">A ReadOnlySpan of bytes in network byte order (Big Endian).</param>
        /// <param name="output">A byte array containing one raw Base58 digit value per byte (i.e. Base58 digit '1' has byte value 0x00 ).</param>
        /// <returns>true on success.</returns>
        public static bool TryGetRawBase58FromBase256(ReadOnlySpan<byte> input, [NotNullWhen(true)] out byte[]? output)
        {
            // Attempting to convert null is probably an error
            if (input == null)
            {
                output = null;
                return false;
            }
            // Empty strings/char[]/byte[] in base256 become empty strings in Base58.
            if (input.Length == 0)
            {
                output = [];
                return true;
            }

            // Count leading zeros (network byte order).
            // Each leading 0x00 becomes a leading '1' in a Base58 string.
            // Inversely, a leading Base58 '1' becomes a leading 8-bit/base256 0x00.
            int leadingZeros = 0;
            while (leadingZeros < input.Length && input[leadingZeros] == 0)
            {
                leadingZeros++;
            }

            // Convert to a number - use BigInteger for potentially very big numbers.
            BigInteger inputValue = new(input[leadingZeros..], true, true);

            // Division loop
            // The remainder from each iteration is inserted before other bytes (i.e. Big Endian)
            // Base10 example: 123 % 58 = 7 (there are 7 'units'), (123/58) % 58 = 2 (there are 2 'tens'), so base10-BE(123) = base58-BE(27).
            // Base58-BE(27) = "38" = HEX-LE(0x7b) = base10-BE(123)
            List<byte> outputValue = [];
            BigInteger remainder;
            while (inputValue > BigInteger.Zero)
            {
                (inputValue, remainder) = BigInteger.DivRem(inputValue, bigInt58);
                outputValue.Insert(0, (byte)remainder);
            }

            // Reinsert leading zeros
            while (leadingZeros > 0)
            {
                outputValue.Insert(0, 0x00);
                leadingZeros--;
            }

            output = [.. outputValue];
            return true;
        }

        /// <summary>
        /// Converts a string into an array of Base58 raw digit values.
        /// </summary>
        /// <param name="input">A string to convert to Base58.</param>
        /// <param name="output">A byte array containing one raw Base58 digit value per byte (i.e. Base58 digit '1' has byte value 0x00).</param>
        /// <returns>true on success.</returns>
        public static bool TryGetRawBase58FromBase58String(string input, [NotNullWhen(true)] out byte[]? output)
        {
            ArgumentNullException.ThrowIfNull(input);
            return TryGetRawBase58FromBase256(Encoding.UTF8.GetBytes(input.Trim()), out output);
        }

        /// <summary>
        /// Converts a ReadOnlySpan of Base58 raw digit values into a Base58 string.
        /// </summary>
        /// <param name="input">A byte array containing one raw Base58 digit value per byte (i.e. Base58 digit '1' has byte value 0x00).</param>
        /// <returns>A Base58 string.</returns>
        public static string GetBase58StringFromRawBase58(ReadOnlySpan<byte> input)
        {
            // Convert Base58 byte values to a Base58 string
            StringBuilder sb = new(input.Length);
            foreach (byte b in input)
            {
                // All valid Base58 byte values are in range 0 through +57
                if (b > 57)
                {
                    throw new ArgumentException("Argument contains non-base58 digit values.", nameof(input));
                }
                sb.Append(base58EncoderAlphabet[b]);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Decodes a Base58 string into a base256 (UTF-8) byte array.
        /// </summary>
        /// <param name="input">A Base58 string, as a ReadOnlySpan of bytes (unsigned chars).</param>
        /// <returns>An array of bytes in network byte order (Big Endian).</returns>
        public static byte[] GetBase256FromBase58String(ReadOnlySpan<byte> input)
        {
            // Attempting to convert null is probably an error
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }
            // Empty strings in Base58 become empty strings/char[]/byte[] in base256.
            if (input.Length == 0)
            {
                return [];
            }

            // Remove leading and trailing whitespace
            input = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(input).Trim());

            // Count leading ones.
            // A leading Base58 '1' becomes a leading 8-bit/base256 0x00.
            int leadingOnes = 0;
            while (leadingOnes < input.Length && input[leadingOnes] == '1')
            {
                leadingOnes++;
            }

            // byte[] are typically in network byte order (Big Endian). Prepending bytes is possible with List<byte>.Insert(0, byteToPrepend).
            List<byte> outputValue = [];
            // Use BigInteger for potentially very big numbers.
            BigInteger inputValue = BigInteger.Zero;

            // Convert array of Base58 digits to a base10 BigInteger
            for (int i = 0; i < input.Length; i++)
            {
                // Get the Base58 byte value for the current UTF-8 Base58 digit
                sbyte base58Value = base58DecoderAlphabet[input[i]];
                // All valid Base58 byte values are in range 0 through +57
                if (base58Value < 0 || base58Value > 57)
                {
                    throw new ArgumentException("Argument contains non-base58 digits.", nameof(input));
                }
                // Base58 strings are Big Endian, so multiply by base (can't left shift) and add the new 'units' value
                inputValue = BigInteger.Multiply(inputValue, bigInt58) + base58Value;
            }
            BigInteger remainder;
            // Convert from base10 BigInteger to base256 byte array
            while (inputValue > 0)
            {
                (inputValue, remainder) = BigInteger.DivRem(inputValue, bigInt256);
                outputValue.Insert(0, (byte)remainder);
            }

            // Add leading zeros
            while (leadingOnes > 0)
            {
                outputValue.Insert(0, 0x00);
                leadingOnes--;
            }

            return [.. outputValue];
        }
    }
}
