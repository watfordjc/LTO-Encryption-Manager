using System;
using System.Diagnostics.CodeAnalysis;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils
{
    public static partial class ByteEncoding
    {
        private const string z85EncoderAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
        private static readonly byte[] z85DecoderAlphabet = [0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47, 0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00];

        /// <summary>
        /// Tries to encode a byte array using Z85-encoding.
        /// </summary>
        /// <param name="input">The bytes to encode using Z85-encoding.</param>
        /// <param name="output">On success, a <see cref="char"/> array containing the Z85-encoded bytes.</param>
        /// <returns><see langword="true"/> on success; otherwise, <see langword="false"/></returns>
        public static bool TryGetToZ85Encoded(ReadOnlySpan<byte> input, [NotNullWhen(true)] out char[]? output)
        {
            if (input == null || input.Length % 4 > 0)
            {
                output = null;
                return false;
            }
            byte[] frame;
            output = new char[input.Length / 4 * 5];
            for (int i = 0; i < input.Length / 4; i++)
            {
                frame = [.. input.Slice(i * 4, 4)];
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(frame);
                }
                uint segmentValue = BitConverter.ToUInt32(frame);
                output[i * 5 + 0] = z85EncoderAlphabet[(int)(segmentValue / 85 / 85 / 85 / 85 % 85)];
                output[i * 5 + 1] = z85EncoderAlphabet[(int)(segmentValue / 85 / 85 / 85 % 85)];
                output[i * 5 + 2] = z85EncoderAlphabet[(int)(segmentValue / 85 / 85 % 85)];
                output[i * 5 + 3] = z85EncoderAlphabet[(int)(segmentValue / 85 % 85)];
                output[i * 5 + 4] = z85EncoderAlphabet[(int)(segmentValue % 85)];
            }
            return true;
        }

		/// <summary>
		/// Tries to decode Z85-encoded data into a byte array.
		/// </summary>
		/// <param name="input">A <see cref="char"/> array containing Z85-encoded bytes.</param>
		/// <param name="output">On success, a Z85-decoded byte array.</param>
		/// <returns><see langword="true"/> on success; otherwise, <see langword="false"/></returns>
		public static bool TryGetFromZ85Encoded(ReadOnlySpan<char> input, [NotNullWhen(true)] out byte[]? output)
        {
            if (input == null || input.Length % 5 > 0)
            {
                output = null;
                return false;
            }
            char[] frame;
            output = new byte[input.Length / 5 * 4];
            for (int i = 0; i < input.Length / 5; i++)
            {
                frame = [.. input.Slice(i * 5, 5)];
                uint segmentValue = 0;
                for (int j = 0; j < 5; j++)
                {
                    segmentValue = segmentValue * 85 + z85DecoderAlphabet[frame[j] - 32];
                }

                byte[] base256 =
                [
                    (byte)(segmentValue / 256 / 256 / 256 % 256),
                    (byte)(segmentValue / 256 / 256 % 256),
                    (byte)(segmentValue / 256 % 256),
                    (byte)(segmentValue % 256),
                ];
                Array.Copy(
                    sourceArray: base256,
                    sourceIndex: 0,
                    destinationArray: output,
                    destinationIndex: i * 4,
                    length: 4);
            }
            return true;
        }
    }
}
