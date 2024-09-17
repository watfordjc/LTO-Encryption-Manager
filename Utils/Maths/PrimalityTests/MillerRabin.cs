using System;
using System.Numerics;
using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths.PrimalityTests
{
	/// <summary>
	/// Provides static methods for determining primality using the Miller-Rabin primality test.
	/// </summary>
	public static class MillerRabin
	{
		/// <summary>
		/// Tests primality of <paramref name="number"/> using the Miller-Rabin primality test.
		/// </summary>
		/// <param name="number">The number to be primality tested.</param>
		/// <param name="compatibilityFlags">Flags to indicate how numbers should be primality tested.</param>
		/// <param name="randomNumberGenerator">The RNG to use for generating witness numbers.</param>
		/// <param name="rounds">The number of rounds of Miller-Rabin testing.</param>
		/// <remarks>
		/// <para>If <see cref="BigPrime.IsSmallPrime"/> is <see langword="true"/> for <paramref name="number"/>, <see langword="true"/> is returned.</para>
		/// <para>If <see cref="BigPrime.IsEven"/> or <see cref="BigPrime.IsPerfectSquare"/> is <see langword="true"/> for <paramref name="number"/>, <see langword="false"/> is returned.</para>
		/// <para>If <paramref name="compatibilityFlags"/> includes <see cref="StandardRSA.Compatibility.PerformMillerRabinTesting"/>, either combine it with the
		///  <see cref="StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds"/> flag and set <paramref name="rounds"/> to <see langword="null"/>,
		///  or specify the number of <paramref name="rounds"/>.</para>
		/// <para>If <paramref name="compatibilityFlags"/> includes <see cref="StandardRSA.Compatibility.PerformLucasTesting"/>, a Lucas test will be performed.</para>
		/// </remarks>
		/// <returns>
		///  <para><see langword="true"/> if a number is probably prime.</para>
		///  <para><see langword="false"/> if a number is likely composite or definitely composite.</para>
		/// </returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="compatibilityFlags"/> contains a flag that is incompatible with the value of 
		///   <paramref name="randomNumberGenerator"/> and/or the value of <paramref name="rounds"/>.</exception>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="rounds"/> is not <see langword="null"/> and is less than 1, or if <paramref name="number"/>
		///   is less than or equal to 1.</exception>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="NotImplementedException">Thrown if <paramref name="compatibilityFlags"/> contains the flag
		///   <see cref="StandardRSA.Compatibility.UseDeterministicMillerRabinForSmallNumbers"/> or
		///   <see cref="StandardRSA.Compatibility.UseDeterministicMillerRabinForLargeNumbers"/>.</exception>
		public static bool IsProbablePrime(BigPrime number, StandardRSA.Compatibility compatibilityFlags, RandomNumberGenerator? randomNumberGenerator = null,
			int? rounds = null)
		{
			ArgumentNullException.ThrowIfNull(number);
			// rounds and StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds are mutually exclusive
			if (rounds is not null && compatibilityFlags.HasFlag(StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds))
			{
				throw new ArgumentException($"Flag {nameof(StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds)} is set, but parameter {nameof(rounds)} is not null.");
			}
			// rounds and StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds are mutually exclusive
			else if (rounds is null && !compatibilityFlags.HasFlag(StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds))
			{
				throw new ArgumentNullException(nameof(rounds), $"Flag {nameof(StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds)} is not set, but parameter {nameof(rounds)} is null.");
			}
			// rounds can't be 0 or negative when specified
			else if (rounds < 1 && !compatibilityFlags.HasFlag(StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds))
			{
				throw new ArgumentOutOfRangeException(nameof(rounds), $"Parameter {nameof(rounds)} must be 1 or greater if not null.");
			}
			// randomNumberGenerator is required if StandardRSA.Compatibility.UseSuppliedRNGForPrimeWitnessNumbers is set
			else if (randomNumberGenerator is null && compatibilityFlags.HasFlag(StandardRSA.Compatibility.UseSuppliedRNGForPrimeWitnessNumbers))
			{
				throw new ArgumentException($"Flag {nameof(StandardRSA.Compatibility.UseSuppliedRNGForPrimeWitnessNumbers)} is set, but parameter {nameof(randomNumberGenerator)} is {randomNumberGenerator}.");
			}
			// StandardRSA.Compatibility.UseDeterministicMillerRabinForSmallNumbers is not implemented
			else if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.UseDeterministicMillerRabinForSmallNumbers))
			{
				throw new NotImplementedException($"Deterministic Miller-Rabin tests are not implemented. {nameof(compatibilityFlags)} contains unsupported flag {nameof(StandardRSA.Compatibility.UseDeterministicMillerRabinForSmallNumbers)}.");
			}
			// StandardRSA.Compatibility.UseDeterministicMillerRabinForLargeNumbers is not implemented
			else if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.UseDeterministicMillerRabinForLargeNumbers))
			{
				throw new NotImplementedException($"Deterministic Miller-Rabin tests are not implemented. {nameof(compatibilityFlags)} contains unsupported flag {nameof(StandardRSA.Compatibility.UseDeterministicMillerRabinForLargeNumbers)}.");
			}

			// Step 1: Handle special cases
			ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(number.Value, 1);
			// Check if the number is a known prime
			if (number.IsSmallPrime)
			{
				return true;
			}
			// Check if the number is even
			else if (number.IsEven)
			{
				return false;
			}
			// Check if a perfect square
			if (number.IsPerfectSquare)
			{
				return false;
			}

			// Step 2: Express 'n-1' as '2^s * d', where d is an odd integer and s is a non-negative integer
			BigInteger numberMinusOne = number.Value - 1;
			// Initialise 'd' to 'n - 1'
			BigInteger d = numberMinusOne;
			// Initialise 's' to 0
			BigInteger s = 0;
			// While 'd' is not odd (LSb is 0), right shift it by 1 and increment 's' by 1, satisfying '2^s * d' = 'n - 1'
			while (d.IsEven)
			{
				d >>>= 1;
				s += 1;
			}

			// Initialise a decrement counter equal to the number of requested rounds of testing
			int testsRemaining;

			//// Create an empty array for 'a' values
			//BigInteger[] aArray = Array.Empty<BigInteger>();

			//if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.UseDeterministicMillerRabinForSmallNumbers))
			//{
			//	// TODO: Implement deterministic tests using known small bases
			//	throw new NotImplementedException($"Deterministic Miller-Rabin tests are not implemented. {nameof(compatibilityFlags)} contains unsupported flag {nameof(StandardRSA.Compatibility.UseDeterministicMillerRabinForSmallNumbers)}.");
			//}
			//if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.UseDeterministicMillerRabinForLargeNumbers))
			//{
			//	// TODO: Implement deterministic Miller-Rabin (very slow)
			//	throw new NotImplementedException($"Deterministic Miller-Rabin tests are not implemented. {nameof(compatibilityFlags)} contains unsupported flag {nameof(StandardRSA.Compatibility.UseDeterministicMillerRabinForLargeNumbers)}.");
			//}

			// If rounds is null, or the flag is set to use the number of rounds PyCryptodome uses for less than E-30 error rate
			if (rounds is null || compatibilityFlags.HasFlag(StandardRSA.Compatibility.UsePyCryptodomeMillerRabinRounds))
			{
				testsRemaining = number.BitLength switch
				{
					< 220 => 30,
					< 280 => 20,
					< 390 => 15,
					< 512 => 10,
					< 620 => 7,
					< 740 => 6,
					< 890 => 5,
					< 1200 => 4,
					< 1700 => 3,
					< 3700 => 2,
					_ => 2
				};
			}
			else
			{
				testsRemaining = rounds.Value;
			}

			// Step 3: The witness loop

			// TODO: Switch to deterministic testing for 'n' < 2^64 (and others) by selecting appropriate hard-coded 'a' for number size

			// Witness number variable 'a'
			BigInteger a;
			// The minimum value for witness number 'a' is 2
			BigInteger aMinimum = 2;
			// Calculate the maximum normalised value for witness number 'a' as '(n - 2) - 2'
			BigInteger normalisedMaximum = number.Value - 2 - aMinimum;
			// Calculate the minimum number of bytes needed to store normalised withness number 'a' across its full range
			int bytesNeeded = normalisedMaximum.GetByteCount(true);
			// Create an appropriately sized byte array to store normalised witness number 'a'
			byte[] normalisedCandidateBytes = new byte[bytesNeeded];

			// Repeat for up to the requested number of tests (non-primes may return early)
			while (testsRemaining > 0)
			{
				// Reset variables
				a = BigInteger.One;
				Array.Clear(normalisedCandidateBytes);

				// Repeat until witness number 'a' is within the desired range
				while (a == BigInteger.One || a == numberMinusOne)
				{
					// Initialise a variable to store a normalised witness number to -1 (outside of desired normalised range)
					BigInteger normalisedCandidate = BigInteger.MinusOne;
					// Repeat until a candidate for a normalised witness number between 1 and 'normalisedMaximum - 1'
					while (normalisedCandidate == BigInteger.MinusOne || normalisedCandidate > normalisedMaximum)
					{
						// Fill the byte array from the RNG
						if (compatibilityFlags.HasFlag(StandardRSA.Compatibility.UseSuppliedRNGForPrimeWitnessNumbers) && randomNumberGenerator is not null)
						{
							randomNumberGenerator.GetBytes(normalisedCandidateBytes);
						}
						else
						{
							RandomNumberGenerator.Fill(normalisedCandidateBytes);
						}
						// Create a normalised BigInteger witness number from the RNG bytes, treating the bytes as big endian unsigned
						normalisedCandidate = new(normalisedCandidateBytes, true, true);
					}
					// Convert the normalised witness number to denormalised witness number 'a'
					a = normalisedCandidate + aMinimum;
				}

				// Calculate 'x' as 'a^d mod n'
				BigInteger x = BigInteger.ModPow(a, d, number.Value);
				// Optimisation: If x is '1' or 'n - 1', the rest of this round won't detect 'n' as composite
				if (x == BigInteger.One || x == numberMinusOne)
				{
					// Decrement the rounds remaining counter
					testsRemaining--;
					// Go to the next round
					continue;
				}

				// Iterate 's' times
				for (int i = 0; i < s; i++)
				{
					// Set 'y' to '(x * x) mod n'
					BigInteger y = BigInteger.ModPow(x, 2, number.Value);
					// If 'x' is a non-trivial square root of '1 modulo n', 'number' is composite
					if (y == BigInteger.One && x != BigInteger.One && x != numberMinusOne)
					{
						// 'n' has a factor
						number.CheckFactor(x - 1);
						// 'number' is definitely composite
						return false;
					}
					// Set 'x' to 'y'
					x = y;
				}

				// If 'x' was not 1 at the end of the last iteration of the for loop, 'number' is likely composite
				if (x != BigInteger.One)
				{
					return false;
				}

				// Decrement the rounds remaining counter
				testsRemaining--;
			}

			// 'number' is probably prime
			return true;
		}
	}
}