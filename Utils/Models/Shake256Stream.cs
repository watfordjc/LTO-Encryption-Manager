using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
	/// <summary>
	/// Provides <see cref="Stream"/> functionality for <see cref="Shake256DRNG"/>.
	/// </summary>
	public class Shake256Stream : Stream
	{
		/// <summary>
		/// Gets a value indicating whether the current stream should be able to read from a seeded <see cref="Shake256DRNG"/> instance.
		/// </summary>
		public bool ShakeAvailable => Shake256Instance.ShakeAvailable;
		/// <inheritdoc cref="Stream.CanRead"/>
		public override bool CanRead => ShakeAvailable && Position <= Length;

		private readonly bool _canSeek;
		/// <inheritdoc cref="Stream.CanSeek"/>
		public override bool CanSeek => _canSeek;
		/// <inheritdoc cref="Stream.CanWrite"/>
		public override bool CanWrite => false;
		/// <inheritdoc cref="Stream.CanTimeout"/>
		public override bool CanTimeout => false;

		private long _length = long.MaxValue;
		/// <inheritdoc cref="Stream.Length"/>
		public override long Length => _length;

		private long _position;
		/// <inheritdoc cref="Stream.Position"/>
		public override long Position { get { return _position; } set { Seek(value, SeekOrigin.Begin); } }

		// Lock object for thread safety
		private readonly object _lockObject = new();
		/// <summary>
		/// The underlying <see cref="Shake256DRNG"/> for the current <see cref="Shake256Stream"/> object.
		/// </summary>
		public Shake256DRNG Shake256Instance { get; init; }

		private Shake256Stream()
		{
			byte[] entropy = RandomNumberGenerator.GetBytes(64);
			Shake256Instance = new(entropy);
		}

		/// <summary>
		/// Initialise a deterministic entropy byte stream from a <see cref="Shake256DRNG"/> object.
		/// </summary>
		/// <param name="shake256">A <see cref="Shake256DRNG"/> object.</param>
		public Shake256Stream(Shake256DRNG shake256)
		{
			Shake256Instance = shake256;
			_canSeek = false;
			_position = 0;
			_length = long.MaxValue;
		}

		/// <inheritdoc cref="Stream.Read(byte[], int, int)"/>
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
				// If ShakeAvailable
				if (ShakeAvailable)
				{
					// Ensure we have enough data to read
					while (count > 0)
					{
						// Try to get the requested amount of output entropy
						byte[] currentHash = new byte[count - bytesRead];
						Shake256Instance.GetBytes(currentHash);
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

				// Return the number of bytes read
				return bytesRead;
			}
		}

		/// <remarks>
		/// <para>Not supported.</para>
		/// </remarks>
		/// <exception cref="NotSupportedException">Thrown if used.</exception>
		[DoesNotReturn]
		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Resets the underlying <see cref="Shake256DRNG"/> so that the current <see cref="Shake256Stream"/> is no longer usable.
		/// </summary>
		public override void Flush()
		{
			// Only allow one thread to Flush(...) at once
			lock (_lockObject)
			{
				Shake256Instance.Reset();
			}
		}

		/// <inheritdoc cref="Stream.Dispose(bool)"/>
		public new void Dispose(bool disposing)
		{
			Shake256Instance?.Dispose();
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

		/// <remarks>
		/// <para>Not supported. Use <seealso cref="SetStreamLength(long)"/> or <seealso cref="ExtendStreamLength(long)"/> instead.</para>
		/// </remarks>
		/// <exception cref="NotSupportedException">Thrown if used.</exception>
		[DoesNotReturn]
		public override void SetLength(long value)
		{
			throw new NotSupportedException();
		}

		/// <remarks>
		/// <para>Not supported.</para>
		/// </remarks>
		/// <exception cref="NotSupportedException">Thrown if used.</exception>
		[DoesNotReturn]
		public override void Write(byte[] buffer, int offset, int count)
		{
			throw new NotSupportedException();
		}
	}
}
