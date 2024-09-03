using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
    public class Shake256Stream : Stream
    {
        private bool _shakeAvailable;
        /// <summary>
        /// Gets a value indicating whether the current stream should be able to read from a seeded Shake256/ShakeDigest instance.
        /// </summary>
        public bool ShakeAvailable { get { return _shakeAvailable; } }
        public override bool CanRead => _shakeAvailable && Position <= Length;

        private readonly bool _canSeek;
        public override bool CanSeek => _canSeek;

        public override bool CanWrite => false;
		public override bool CanTimeout => false;

		private long _length = long.MaxValue;
        public override long Length => _length;

        private long _position;
        public override long Position { get { return _position; } set { Seek(value, SeekOrigin.Begin); } }

        // Create a Shake256 (dotnet) instance if Shake256 is supported
        private readonly Shake256? shake256 = Shake256.IsSupported ? new() : null;
        // Create a ShakeDigest (BouncyCastle) instance if Shake256 is not supported
        private readonly ShakeDigest? shakeDigest = !Shake256.IsSupported ? new(256) : null;
        // Lock object for thread safety
        private readonly object _lockObject = new();

        private Shake256Stream() { }

		/// <summary>
		/// Initialise a determinstic entropy byte stream from a <see cref="Bip32Node"/> that has a BIP-0085 derivation path.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
        /// <param name="canSeek">Sets the value of <see cref="CanSeek"/>.</param>
        /// <remarks>
        /// <para>NB: Setting <paramref name="canSeek"/> to <c>true</c> is not advisable due to security and performance concerns.</para>
        /// <para>If you do not need to use <see cref="Seek(long, SeekOrigin)"/>, use <seealso cref="Shake256Stream(Bip32Node)"/> instead.</para>
        /// </remarks>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have the following conditions: <see cref="Bip32Node.IsInitialised"/> is <c>false</c>, <see cref="Bip32Node.IsHardenedNode"/> is <c>false</c>, <see cref="Bip32Node.DerivationPath"/> is not a BIP-0085 derivation path (i.e. does not start with "<c>m/83696968H/</c>").</exception>
		/// <exception cref="PlatformNotSupportedException">Thrown if Shake256 (dotnet) and ShakeDigest (BouncyCastle) are not available.</exception>
		public Shake256Stream(Bip32Node node, bool canSeek)
        {
            _canSeek = canSeek;
            Initialise(node);
        }

		/// <summary>
		/// Initialise a determinstic entropy byte stream from a <see cref="Bip32Node"/> that has a BIP-0085 derivation path.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <exception cref="ArgumentException">
		/// Thrown if <paramref name="node"/> does not have the following conditions: <see cref="Bip32Node.IsInitialised"/> is <c>false</c>,
		///  <see cref="Bip32Node.IsHardenedNode"/> is <c>false</c>, <see cref="Bip32Node.DerivationPath"/> is not a BIP-0085 derivation path
		///   (i.e. does not start with "<c>m/83696968H/</c>").
		/// </exception>
		/// <exception cref="PlatformNotSupportedException">Thrown if Shake256 (dotnet) and ShakeDigest (BouncyCastle) are not available.</exception>
		public Shake256Stream(Bip32Node node)
        {
            Initialise(node);
        }

        private void Initialise(Bip32Node node)
        {
            // Seed the Shake256 instance
            SeedShake(node);
        }

		/// <summary>
		/// Re-initialise a determinstic entropy byte stream from a <see cref="Bip32Node"/> that has a BIP-0085 derivation path.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <remarks>
		/// <para>This <see cref="Stream"/> wrapper around <see cref="Shake256"/>/<see cref="ShakeDigest"/> only allows seeding with
		///  64 bytes derived using <see cref="Bip85.GetEntropy(Bip32Node, int)"/>.</para>
		/// <para>If <see cref="ShakeAvailable"/> is <c>true</c>, calling this method will result in an exception - call <see cref="Flush"/>
		///  before reinitialising with a different <see cref="Bip32Node"/></para>
		/// </remarks>
		/// <exception cref="ArgumentException">
        /// Thrown if <paramref name="node"/> does not have the following conditions:
        ///   <see cref="Bip32Node.IsInitialised"/> is <c>false</c>,
        ///   <see cref="Bip32Node.IsHardenedNode"/> is <c>false</c>,
        ///   <see cref="Bip32Node.DerivationPath"/> is not a BIP-0085 derivation path (i.e. does not start with "<c>m/83696968H/</c>").
        /// </exception>
		/// <exception cref="InvalidOperationException">Thrown if <see cref="ShakeAvailable"/>is true.</exception>
		/// <exception cref="PlatformNotSupportedException">Thrown if Shake256 (dotnet) and ShakeDigest (BouncyCastle) are not available.</exception>
		public void SeedShake(Bip32Node node)
        {
            // Only allow one thread to SeedShake(...) at once
            lock (_lockObject)
            {
                ArgumentNullException.ThrowIfNull(node);
                if (!node.IsInitialised)
                {
                    throw new ArgumentException("Node must be initialised.", nameof(node));
                }
                else if (!node.IsHardenedNode)
                {
                    throw new ArgumentException("Node must be obtained using hardened derivation.", nameof(node));
                }
                else if (!node.DerivationPath.StartsWith("m/83696968H/", StringComparison.Ordinal))
                {
                    throw new ArgumentException("Node must have a BIP-0085 derivation path.", nameof(node));
                }

                // Use BIP-0085 entropy-from-k to get 64 bytes of entropy for Shake256
                ReadOnlySpan<byte> inputEntropy = Bip85.GetEntropy(node, HMACSHA512.HashSizeInBytes);

                // Use Shake256 (dotnet) if available
                if (Shake256.IsSupported && shake256 is not null && !_shakeAvailable)
                {
                    // Feed in the input entropy
                    shake256.AppendData(inputEntropy);
                    _position = 0;
                    _length = long.MaxValue;
                    _shakeAvailable = true;
                }
                // Use ShakeDigest (BouncyCastle) if Shake256 (dotnet) is not available
                else if (!Shake256.IsSupported && shakeDigest is not null && !_shakeAvailable)
                {
                    // Feed in the input entropy
                    shakeDigest.BlockUpdate([.. inputEntropy], 0, inputEntropy.Length);
					_position = 0;
					_length = long.MaxValue;
					_shakeAvailable = true;
                }
                else
                {
                    if (_shakeAvailable)
                    {
                        throw new InvalidOperationException($"This {nameof(Shake256Stream)} instance is already initialised with another {nameof(Bip32Node)}. You need to call {nameof(Flush)} before reinitialising with another {nameof(Bip32Node)}.");
                    }
                    else
                    {
                        throw new PlatformNotSupportedException($"Neither {nameof(Shake256)} or {nameof(ShakeDigest)} is available.");
                    }
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // Only allow one thread to Read(...) at once
            lock (_lockObject)
            {
                // Check buffer is not null
                ArgumentNullException.ThrowIfNull(buffer);
                // End of data reached
                if (Position == Length)
                {
                    return 0;
                }
                // Check buffer is big enough
                if (buffer.Length < offset + count)
                {
                    throw new ArgumentException("Buffer is too small.", nameof(buffer));
                }
                // Make sure we don't exceed the 'end' of the stream
                count = (int)Math.Min(count, Length - Position);

                // Keep track of how many bytes have been read
                int bytesRead = 0;
                // Keep track of how many times we've read 0 bytes
                int zeroBytesReadCount = 0;
                // Maximum number of 0 byte reads in a row
                int zeroByteReadMaxCount = 5;
                // If Shake256 is used
                if (Shake256.IsSupported && shake256 is not null)
                {
                    // Ensure we have enough data to read
                    while (count > 0)
                    {
                        // Try to get the requested amount of output entropy
                        byte[] currentHash = shake256.GetCurrentHash(count);
                        //// Update our 0 byte read count
                        zeroBytesReadCount = currentHash.Length > 0 ? 0 : zeroBytesReadCount + 1;
                        // Throw an exception if we've read 0 bytes too many times in a row
                        if (zeroBytesReadCount == zeroByteReadMaxCount)
                        {
                            throw new CryptographicException($"Shake256.GetCurrentHash has returned 0 bytes {zeroBytesReadCount} times in a row - maximum number of sequential 0 byte reads allowed is {zeroByteReadMaxCount}.");
                        }
                        // Update the total number of bytes read for this call of Read()
                        bytesRead += currentHash.Length;
                        // Copy the read bytes into the output buffer
                        Array.Copy(currentHash, 0, buffer, offset, currentHash.Length);
                        // Reduce the number of bytes still needed by the number of bytes read
                        count -= currentHash.Length;
                        // Increase our start offset by the number of bytes read
                        offset += currentHash.Length;
                        // Update our position in the stream
                        _position += currentHash.Length;
                    }
                }
                // If ShakeDigest is used
                else if (shakeDigest is not null)
                {
                    // Ensure we have enough data to read
                    while (count > 0)
                    {
                        // Try to get the requested amount of output entropy
                        int newBytesRead = shakeDigest.Output(buffer, offset, count);
                        // Update our 0 byte read count
                        zeroBytesReadCount = newBytesRead > 0 ? 0 : zeroBytesReadCount + 1;
                        // Throw an exception if we've read 0 bytes too many times in a row
                        if (zeroBytesReadCount == zeroByteReadMaxCount)
                        {
                            throw new CryptographicException($"ShakeDigest.Output has returned 0 bytes {zeroBytesReadCount} times in a row - maximum number of sequential 0 byte reads allowed is {zeroByteReadMaxCount}.");
                        }
                        // Update the total number of bytes read for this call of Read()
                        bytesRead += newBytesRead;
                        // Reduce the number of bytes still needed by the number of bytes read
                        count -= newBytesRead;
                        // Increase our start offset by the number of bytes read
                        offset += newBytesRead;
                        // Update our position in the stream
                        _position += newBytesRead;
                    }
                }

                // Return the number of bytes read
                return bytesRead;
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            // Only allow one thread to Seek(...) at once
            lock (_lockObject)
            {
                long seekPosition = origin switch
                {
                    SeekOrigin.Begin => offset,
                    SeekOrigin.Current => Position + offset,
                    SeekOrigin.End => Length + offset,
                    _ => throw new NotSupportedException()
                };

                if (seekPosition < Position)
                {
                    throw new NotSupportedException();
                }
                else if (seekPosition > Position)
                {
                    byte[] buffer = new byte[4096];
                    while (Position < seekPosition)
                    {
                        Read(buffer, 0, (int)Math.Min(buffer.Length, seekPosition - Position));
                    }
                    Array.Clear(buffer);
                }
                return Position;
            }
		}

		public override void Flush()
		{
			// Only allow one thread to Flush(...) at once
			lock (_lockObject)
			{
				shake256?.GetHashAndReset(0);
				shakeDigest?.Reset();
				_shakeAvailable = false;
			}
		}

		public new void Dispose(bool disposing)
		{
			shake256?.Dispose();
			base.Dispose(disposing);
		}

		/// <summary>
		/// Sets the <see cref="Length"/> of the stream to <paramref name="value"/>.
		/// </summary>
		/// <param name="value">The desired length of the stream in bytes.</param>
		/// <remarks>
		/// <para>NB: The maximum (and initial) value of <see cref="Length"/> is <see cref="long.MaxValue"/>.</para>
		/// <para>See also: <seealso cref="ExtendStreamLength(long)"/></para>
		/// </remarks>
		public void SetStreamLength(long value)
        {
            // Only allow one thread to SetStreamLength(...) at once
            lock (_lockObject)
            {
                _length = value;
            }
        }

        /// <summary>
        /// Extends the current <see cref="Length"/> of the stream by <paramref name="value"/> bytes.
        /// </summary>
        /// <param name="value">The number of bytes to extend the <see cref="Length"/> by.</param>
        /// <returns>The new value of <see cref="Length"/>.</returns>
        /// <remarks>
        /// <para>NB: If the sum of <see cref="Position"/> and <paramref name="value"/> exceeds <see cref="long.MaxValue"/>,
        ///  <see cref="Length"/> will be set to <see cref="long.MaxValue"/>.</para>
        /// <para>See also: <seealso cref="SetStreamLength(long)"/></para>
        /// </remarks>
        public long ExtendStreamLength(long value)
        {
            // Only allow one thread to ExtendStreamLength(...) at once
            lock (_lockObject)
            {
                long maxExtension = long.MaxValue - Position;
                long calculatedExtension = value > maxExtension ? long.MaxValue : Length + value;
                SetStreamLength(calculatedExtension);
                return Length;
            }
        }

		/// <exception cref="NotSupportedException">Thrown if used.</exception>
		/// <remarks>
		/// <para>Not supported. Use <seealso cref="SetStreamLength(long)"/> or <seealso cref="ExtendStreamLength(long)"/> instead.</para>
		/// </remarks>
        [DoesNotReturn]
		public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        /// <exception cref="NotSupportedException">Thrown if used.</exception>
        /// <remarks>
        /// <para>Not supported. Use <seealso cref="Flush"/> followed by <see cref="SeedShake(Bip32Node)"/> instead.</para>
        /// </remarks>
        [DoesNotReturn]
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
