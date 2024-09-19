using System;
using System.Numerics;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;
using System.Security.Cryptography;
#if DEBUG
using System.Diagnostics;
using System.Globalization;
#endif

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public partial class BigPrime
	{
		/// <summary>
		/// Delegate for callback methods passed to <see cref="Create(int, StandardRSA.Compatibility, RandomNumberGenerator?, ConductPrimalityTestCallback?)"/>.
		/// </summary>
		/// <remarks>
		/// <para>If a method matching this delegate is passed as a parameter to <see cref="Create(int, StandardRSA.Compatibility, RandomNumberGenerator?, ConductPrimalityTestCallback?)"/>,
		///  the method will be called during random number generation so that the calling function can indicate whether to test the current random number for primality.</para>
		/// </remarks>
		/// <param name="candidate">The current random number that is about to be tested for primality.</param>
		/// <param name="primeBitLength">The value of the <paramref name="primeBitLength"/> parameter when <see cref="Create(int, StandardRSA.Compatibility, RandomNumberGenerator?, ConductPrimalityTestCallback?)"/>
		///  was called.</param>
		/// <returns><see langword="true"/> if <paramref name="candidate"/> should be primality tested; <see langword="false"/> if <paramref name="candidate"/> should not
		///  be primality tested.</returns>
		public delegate bool ConductPrimalityTestCallback(BigInteger candidate, int primeBitLength);

#if DEBUG
		/// <summary>
		/// Finds the next (probable) prime number in a <see cref="Shake256Stream"/> that is <paramref name="primeBitLength"/> bits long.
		/// </summary>
		/// <remarks>
		///  <para>Only available in DEBUG builds. Use <seealso cref="Create(int, StandardRSA.Compatibility, RandomNumberGenerator?, ConductPrimalityTestCallback?)"/>
		///   with a <see cref="Shake256DRNG"/> (e.g. <see cref="Shake256Stream.Shake256Instance"/>) for non-DEBUG builds.</para>
		///  <para>This method includes additional output, including the <see cref="Shake256Stream.Position"/> the prime number was located at, which may be useful when
		///   debugging determinism issues.</para>
		/// </remarks>
		/// <param name="primeBitLength">The requested length in bits for the prime number.</param>
		/// <param name="compatibilityFlags">Flags to indicate how prime numbers should be generated and primality tested.</param>
		/// <param name="shake256Stream">A <see cref="Shake256Stream"/> for which <see cref="Shake256Stream.ShakeAvailable"/> is <see langword="true"/>.</param>
		/// <param name="conductPrimalityTestCallback">A function called with a potential candidate number and the value of <paramref name="primeBitLength"/>
		///  so that the calling function can reject the candidate number before primality testing commences.</param>
		/// <returns>The next probable prime number in <paramref name="shake256Stream"/> that is <paramref name="primeBitLength"/> bits long.</returns>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="primeBitLength"/> is less than 8.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="shake256Stream"/> cannot be read from.</exception>
		public static BigPrime Create(int primeBitLength, StandardRSA.Compatibility compatibilityFlags, Shake256Stream shake256Stream,
			ConductPrimalityTestCallback? conductPrimalityTestCallback)
		{
			ArgumentNullException.ThrowIfNull(shake256Stream);
			if (!shake256Stream.CanRead)
			{
				throw new ArgumentException("Cannot read bytes from stream.", nameof(shake256Stream));
			}
			// Starting position in entropy stream
			long startPosition = shake256Stream.Position;
			BigPrime primeNumber = Create(primeBitLength, compatibilityFlags, shake256Stream.Shake256Instance, conductPrimalityTestCallback);
			long entropyConsumed = shake256Stream.Position - startPosition;
			Trace.WriteLine($"  * Possible {primeBitLength}-bit prime found after {entropyConsumed} bytes ({string.Format(CultureInfo.CurrentCulture, "{0:0.000}", (double)entropyConsumed / 1048576)} MiB) of entropy consumed from DRNG.");
			return primeNumber;
		}
#endif

		/// <summary>
		/// Finds a (probable) prime number in a <see cref="RandomNumberGenerator"/> that is <paramref name="primeBitLength"/> bits long.
		/// </summary>
		/// <param name="primeBitLength">The requested length in bits for the prime number.</param>
		/// <param name="compatibilityFlags">Flags to indicate how prime numbers should be generated and primality tested.</param>
		/// <param name="randomNumberGenerator">A <see cref="RandomNumberGenerator"/> or derived class instance.</param>
		/// <param name="conductPrimalityTestCallback">A function called with a potential candidate number and the value of <paramref name="primeBitLength"/>
		///  so that the calling function can reject the candidate number before primality testing commences.</param>
		/// <returns>The next (probable) prime number in <paramref name="randomNumberGenerator"/> that is <paramref name="primeBitLength"/> bits long.</returns>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="primeBitLength"/> is less than 8.</exception>
		public static BigPrime Create(int primeBitLength, StandardRSA.Compatibility compatibilityFlags, RandomNumberGenerator? randomNumberGenerator,
			ConductPrimalityTestCallback? conductPrimalityTestCallback)
		{
			ArgumentOutOfRangeException.ThrowIfLessThan(primeBitLength, 8, nameof(primeBitLength));
			// Count the number of whole bytes needed
			int wholeBytesNeeded = primeBitLength / 8;
			// Count the number of extra bits needed
			int remainderBits = primeBitLength % 8;
			// The size of a right shift needed after adding one extra byte of bits
			int rightShift = remainderBits == 0 ? 0 : 8 - remainderBits;
			// If the number of bits isn't a whole number of bytes, we need an extra 1 byte
			int extraByteNeeded = remainderBits > 0 ? 1 : 0;

			// Create a bitmask based on what bits we want our prime to have set
			BigInteger requiredBitsBitmask = BigInteger.One << (primeBitLength - 1) | BigInteger.One;
			requiredBitsBitmask |= compatibilityFlags.HasFlag(StandardRSA.Compatibility.RequireSecondMostSignificantBit) ? BigInteger.One << (primeBitLength - 2) : BigInteger.Zero;

			// Create a bitmask for the bits we want to forcefully set on our random numbers
			BigInteger forcedBitsBitmask = BigInteger.Zero;
			forcedBitsBitmask |= compatibilityFlags.HasFlag(StandardRSA.Compatibility.SetMostSignificantBit) ? BigInteger.One << (primeBitLength - 1) : BigInteger.Zero;
			forcedBitsBitmask |= compatibilityFlags.HasFlag(StandardRSA.Compatibility.SetSecondMostSignificantBit) ? BigInteger.One << (primeBitLength - 2) : BigInteger.Zero;
			forcedBitsBitmask |= compatibilityFlags.HasFlag(StandardRSA.Compatibility.SetLeastSignificantBit) ? BigInteger.One : BigInteger.Zero;

			// Array to hold our entropy bytes
			byte[] currentEntropyBytes = new byte[wholeBytesNeeded + extraByteNeeded];
			// Variable to hold the prime number
			BigPrime? bigPrime = null;
			// Check if a weak prime (Fermat number) is possible for this bit length
			bool fermatNumberPossible = BigIntegerExtensions.TryGetFermatNumberForBitLength(primeBitLength, out BigInteger? fermatNumber);
			// Calculate the Mersenne number with this bit length
			BigInteger mersenneNumber = (BigInteger.One << primeBitLength) - 1;

			// We need an integer that is a probable prime
			while (bigPrime is null || !bigPrime.IsProbablePrime.GetValueOrDefault(false))
			{
				// Read entropy into array
				if (randomNumberGenerator is not null)
				{
					randomNumberGenerator.GetBytes(currentEntropyBytes);
				}
				else
				{
					RandomNumberGenerator.Fill(currentEntropyBytes);
				}

				// Convert the entropy to a big integer
				BigInteger potentialPrime = new(currentEntropyBytes, true, true);
				// Right shift so the number is the desired bit length
				potentialPrime >>= rightShift;
				// OR our number with the bits we want to forcefully set on all numbers
				potentialPrime |= forcedBitsBitmask;

				// Discard the number if it doesn't have our required bits set
				if ((potentialPrime & requiredBitsBitmask) != requiredBitsBitmask)
				{
					continue;
				}
				// Rule out Fermat numbers, even if they might be prime
				else if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.RejectFermatNumbers) && fermatNumberPossible && potentialPrime == fermatNumber)
				{
					continue;
				}
				// Rule out Mersenne numbers, even if they might be prime
				else if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.RejectMersenneNumbers) && potentialPrime == mersenneNumber)
				{
					continue;
				}
				// Deterministic small divisors test
				foreach (uint smallPrime in BigPrime.First100Primes)
				{
					if (potentialPrime % smallPrime == 0)
					{ 
						continue;
					}
				}
				if (conductPrimalityTestCallback is not null && !conductPrimalityTestCallback(potentialPrime, primeBitLength))
				{
					continue;
				}
				// Create a BigPrime from the BigInteger, passing in the compatibility flags (includes primality testing method flags)
				bigPrime = new(potentialPrime, compatibilityFlags);
				// Test the BigPrime for primality per the primality flags
				bigPrime.CheckPrimality(null, randomNumberGenerator);
			}

			return bigPrime;
		}
	}
}
