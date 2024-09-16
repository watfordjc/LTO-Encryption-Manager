using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.ImprovementProposals.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
	/// <summary>
	/// Provides functionality for providing deterministically pseudorandom values.
	/// </summary>
	public class Shake256DRNG : RandomNumberGenerator
	{
		private bool _shakeAvailable;
		/// <summary>
		/// Gets a value indicating whether the underlying SHAKE-256 instance should be able to be read from.
		/// </summary>
		public bool ShakeAvailable { get { return _shakeAvailable; } }
		// Create a Shake256 (dotnet) instance if Shake256 is supported
		private readonly Shake256? shake256 = Shake256.IsSupported ? new() : null;
		// Create a ShakeDigest (BouncyCastle) instance if Shake256 is not supported
		private readonly ShakeDigest? shakeDigest = !Shake256.IsSupported ? new(256) : null;
		// Lock object for thread safety
		private readonly object _lockObject = new();

		/// <summary>
		/// Create a deterministic SHAKE-256 instance seeded using the specified bytes.
		/// </summary>
		/// <param name="seedEntropy">A span of at least 64 bytes containing the entropy that will be used to see the DRNG.</param>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="seedEntropy"/> has a byte length that is less than 64.</exception>
		/// <exception cref="PlatformNotSupportedException">Thrown if Shake256 (dotnet) and ShakeDigest (BouncyCastle) are not available.</exception>
		private void Create(ReadOnlySpan<byte> seedEntropy)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(seedEntropy.Length, 64, nameof(seedEntropy.Length));
			// Use Shake256 (dotnet) if available
			if (Shake256.IsSupported && shake256 is not null)
			{
				// Feed in the input entropy
				shake256.AppendData(seedEntropy);
				_shakeAvailable = true;
			}
			// Use ShakeDigest (BouncyCastle) if Shake256 (dotnet) is not available
			else if (!Shake256.IsSupported && shakeDigest is not null)
			{
				// Feed in the input entropy
				shakeDigest.BlockUpdate([.. seedEntropy], 0, seedEntropy.Length);
				_shakeAvailable = true;
			}
			// Unable to create an instance of Shake256/ShakeDigest
			else
			{
				throw new PlatformNotSupportedException($"Neither {nameof(Shake256)} or {nameof(ShakeDigest)} is available.");
			}
		}

		/// <summary>
		/// Create a deterministic SHAKE-256 instance seeded using 64 bytes from <see cref="RandomNumberGenerator.GetBytes(int)"/>.
		/// </summary>
		/// <exception cref="PlatformNotSupportedException">Thrown if Shake256 (dotnet) and ShakeDigest (BouncyCastle) are not available.</exception>
		public Shake256DRNG()
		{
			// Create 64 bytes of entropy
			byte[] seedEntropy = GetBytes(64);
			Create(seedEntropy);
		}

		/// <summary>
		/// Create a deterministic SHAKE-256 instance seeded using the specified bytes.
		/// </summary>
		/// <param name="seedEntropy">A span of at least 64 bytes containing the entropy that will be used to see the DRNG.</param>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="seedEntropy"/> has a byte length that is less than 64.</exception>
		/// <exception cref="PlatformNotSupportedException">Thrown if Shake256 (dotnet) and ShakeDigest (BouncyCastle) are not available.</exception>
		public Shake256DRNG(ReadOnlySpan<byte> seedEntropy)
		{
			Create(seedEntropy);
		}

		/// <summary>
		/// Create a deterministic SHAKE-256 entropy byte stream seeded using BIP85 bip-entropy-from-k and a <see cref="Bip32Node"/> that has a BIP-0085 derivation path.
		/// </summary>
		/// <param name="node">A <see cref="Bip32Node"/> with a BIP-0085 derivation path.</param>
		/// <exception cref="ArgumentException">Thrown if <paramref name="node"/> does not have the following conditions:
		///   <see cref="Bip32Node.IsInitialised"/> is <see langword="false"/>,
		///   <see cref="Bip32Node.IsHardenedNode"/> is <see langword="false"/>,
		///   <see cref="Bip32Node.DerivationPath"/> is not a BIP-0085 derivation path (i.e. does not start with "<c>m/83696968H/</c>").
		/// </exception>
		/// <exception cref="PlatformNotSupportedException">Thrown if Shake256 (dotnet) and ShakeDigest (BouncyCastle) are not available.</exception>
		public Shake256DRNG(Bip32Node node)
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

			// Use BIP-0085 bip-entropy-from-k to get 64 bytes of entropy
			ReadOnlySpan<byte> inputEntropy = Bip85.GetEntropy(node, HMACSHA512.HashSizeInBytes);
			// Create an instance of SHAKE-256 using the entropy as the seed
			Create(inputEntropy);
		}

		/// <inheritdoc cref="RandomNumberGenerator.GetBytes(byte[])"/>
		public override void GetBytes(byte[] data)
		{
			// Only allow one thread to GetBytes(...) at once
			lock (_lockObject)
			{
				// Require non-nullable parameters not be null
				ArgumentNullException.ThrowIfNull(data);
				if (!ShakeAvailable)
				{
					throw new InvalidOperationException($"{nameof(Reset)} has previously been called on this instance of {nameof(Shake256DRNG)}.");
				}
				// If Shake256 is used
				if (Shake256.IsSupported && shake256 is not null)
				{
					// Create a temporary buffer to hold the Shake256 output
					byte[] buffer = new byte[data.Length];
					// Fill the buffer with Shake256 output
					buffer = shake256.GetCurrentHash(buffer.Length);
					// Copy the bytes in the buffer to the array supplied in the data parameter
					Array.Copy(buffer, data, buffer.Length);
				}
				// If ShakeDigest is used
				else if (shakeDigest is not null)
				{
					// Create a temporary buffer to hold the Shake256 output
					byte[] buffer = new byte[data.Length];
					// Fill the buffer with ShakeDigest output
					shakeDigest.Output(buffer, 0, buffer.Length);
					// Copy the bytes in the buffer to the array supplied in the data parameter
					Array.Copy(buffer, data, buffer.Length);
				}
			}
		}

		/// <inheritdoc cref="RandomNumberGenerator.GetBytes(byte[], int, int)"/>
		public override void GetBytes(byte[] data, int offset, int count)
		{
			// Only allow one thread to GetBytes(...) at once
			lock (_lockObject)
			{
				// Require non-nullable parameters not be null
				ArgumentNullException.ThrowIfNull(data);
				ArgumentOutOfRangeException.ThrowIfGreaterThan(count, data.Length - offset, nameof(count));
				if (!ShakeAvailable)
				{
					throw new InvalidOperationException($"{nameof(Reset)} has previously been called on this instance of {nameof(Shake256DRNG)}.");
				}
				byte[] buffer = new byte[count];
				GetBytes(buffer);
				Array.Copy(buffer, data, count);
			}
		}

		/// <remarks><para>Not supported.</para></remarks>
		/// <param name="data"></param>
		/// <exception cref="NotImplementedException">Thrown if this method is used.</exception>
		[DoesNotReturn]
		public override void GetNonZeroBytes(byte[] data)
		{
			throw new NotImplementedException();
			//base.GetNonZeroBytes(data);
		}


		/// <remarks><para>Not supported.</para></remarks>
		/// <param name="data"></param>
		/// <exception cref="NotImplementedException">Thrown if this method is used.</exception>
		[DoesNotReturn]
		public override void GetNonZeroBytes(Span<byte> data)
		{
			throw new NotImplementedException();
			//base.GetNonZeroBytes(data);
		}

		/// <summary>
		/// Resets this instance of <see cref="Shake256DRNG"/>, clearing the state of the underlying <see cref="Shake256"/>/<see cref="ShakeDigest"/> instance.
		/// </summary>
		/// <remarks>
		/// <para>As <see cref="Shake256DRNG"/> does not retain the initial entropy or have a method to reseed the underlying SHAKE-256 instance, no more data can be read from this instance of <see cref="Shake256DRNG"/> after this method has been called.</para>
		/// </remarks>
		public void Reset()
		{
			// Only allow one thread to Clear(...) at once
			lock (_lockObject)
			{
				shake256?.GetHashAndReset(0);
				shakeDigest?.Reset();
				_shakeAvailable = false;
			}
		}

		/// <inheritdoc cref="RandomNumberGenerator.Dispose(bool)"/>
		protected override void Dispose(bool disposing)
		{
			Reset();
			shake256?.Dispose();
			base.Dispose(disposing);
		}
	}
}
