using System;
using System.Diagnostics.CodeAnalysis;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Wallet
{
    public static class Z85
    {
        private static readonly string encoderAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
        private static readonly byte[] decoderAlphabet = { 0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00, 0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47, 0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00 };

        public static bool TryGetEncodedBytes(ReadOnlySpan<byte> input, [NotNullWhen(true)] out byte[]? output)
        {
            if (input == null || input.Length % 4 > 0)
            {
                output = null;
                return false;
            }
            byte[] frame;
            output = new byte[input.Length / 4 * 5];
            for (int i = 0; i < input.Length / 4; i++)
            {
                frame = input.Slice(i * 4, 4).ToArray();
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(frame);
                }
                uint segmentValue = BitConverter.ToUInt32(frame);
                output[(i * 5) + 0] = (byte)encoderAlphabet[(int)(segmentValue / 85 / 85 / 85 / 85 % 85)];
                output[(i * 5) + 1] = (byte)encoderAlphabet[(int)(segmentValue / 85 / 85 / 85 % 85)];
                output[(i * 5) + 2] = (byte)encoderAlphabet[(int)(segmentValue / 85 / 85 % 85)];
                output[(i * 5) + 3] = (byte)encoderAlphabet[(int)(segmentValue / 85 % 85)];
                output[(i * 5) + 4] = (byte)encoderAlphabet[(int)(segmentValue % 85)];
            }
            return true;
        }

        public static bool TryGetDecodedBytes(ReadOnlySpan<byte> input, [NotNullWhen(true)] out byte[]? output)
        {
            if (input == null || input.Length % 5 > 0)
            {
                output = null;
                return false;
            }
            byte[] frame;
            output = new byte[input.Length / 5 * 4];
            for (int i = 0; i < input.Length / 5; i++)
            {
                frame = input.Slice(i * 5, 5).ToArray();
                uint segmentValue = 0;
                for (int j = 0; j < 5; j++)
                {
                    segmentValue = segmentValue * 85 + decoderAlphabet[frame[j] - 32];
                }

                byte[] base256 = new byte[4];
                base256[0] = (byte)(segmentValue / 256 / 256 / 256 % 256);
                base256[1] = (byte)(segmentValue / 256 / 256 % 256);
                base256[2] = (byte)(segmentValue / 256 % 256);
                base256[3] = (byte)(segmentValue % 256);
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
