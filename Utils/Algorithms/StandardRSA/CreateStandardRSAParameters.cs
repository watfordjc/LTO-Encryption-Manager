using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	/// <summary>
	/// Provides static methods for generating <see cref="RSAParameters"/>.
	/// </summary>
	public static partial class StandardRSA
	{
		/// <summary>
		/// Generates an <see cref="RSAParameters"/> instance, if possible, using BIP85 deterministic RSA key generation.
		/// </summary>
		/// <param name="keyBitLength">The RSA public modulus key length to generate, in bits.</param>
		/// <param name="randomNumberGenerator">A <see cref="Shake256Stream"/> for which <see cref="Shake256Stream.ShakeAvailable"/> is <see langword="true"/>.</param>
		/// <param name="compatibilityFlags">Compatibility flags that adjust how deterministic prime number and asymmetric key generation is performed.</param>
		/// <returns>An <see cref="RSAParameters"/> instance on success, otherwise <see langword="null"/>.</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="keyBitLength"/> is an invalid RSA key length.</exception>
		/// <exception cref="ArgumentNullException">Thrown if a non-nullable parameter is <see langword="null"/>.</exception>
		/// <exception cref="UnreachableException">Thrown if code that should be unreachable is reached.</exception>
		public static RSAParameters CreateStandardRSAParameters(int keyBitLength, StandardRSA.Compatibility compatibilityFlags, RandomNumberGenerator? randomNumberGenerator)
		{

			// Check key length is acceptable, using RSACryptoServiceProvider to get key length rules
			using RSACryptoServiceProvider rsaCryptoServiceProvider = new();
			KeySizes[] legalKeySizes = rsaCryptoServiceProvider.LegalKeySizes;
			if (keyBitLength < legalKeySizes[0].MinSize || keyBitLength > legalKeySizes[0].MaxSize || keyBitLength % legalKeySizes[0].SkipSize != 0)
			{
				throw new ArgumentException("Invalid key length.", nameof(keyBitLength));
			}

			// For Standard RSA, two primes p and q are used. We want primes that are half the key length (in bits) so their product is not longer than the key length
			int primeBitLength = keyBitLength / 2;
			// Store potential primes in a sorted set, so that "p > q" (or "p < q") can be ensured
			SortedSet<BigPrime> primes = [];
			// The sorted position of P
			int pIndex = compatibilityFlags.HasFlag(StandardRSA.Compatibility.RSAPrimeQGreaterThanPrimeP) ? 0 : 1;
			// The sorted position of Q
			int qIndex = compatibilityFlags.HasFlag(StandardRSA.Compatibility.RSAPrimeQGreaterThanPrimeP) ? 1 : 0;
			// A parameter to store the return value
			RSAParameters? rsaParameters = null;

			while (rsaParameters is null)
			{
				// Clear our SortedSet from any previous iterations
				primes.Clear();

				// If the DRNG is not being used for Miller-Rabin witness numbers, it is only being used to generate primes
				if (!compatibilityFlags.HasFlag(StandardRSA.Compatibility.UseSuppliedRNGForPrimeWitnessNumbers))
				{
					// Start two tasks/threads to find two primes
					Task<BigPrime>[] tasks =
					[
						Task.Run(() => BigPrime.Create(primeBitLength, compatibilityFlags, randomNumberGenerator, null)),
						Task.Run(() => BigPrime.Create(primeBitLength, compatibilityFlags, randomNumberGenerator, null))
					];

					// Wait for all tasks to complete
					Task.WaitAll(tasks);
					// Store the results from the tasks in the SortedSet
					foreach (Task<BigPrime> primeTask in tasks)
					{
						primes.Add(primeTask.Result);
					}
				}
				// Replicated PyCryptodome behaviour
				else
				{
					// First, search for a suitable prime for 'p', passing a pre-primality-check callback
					BigPrime prime1 = BigPrime.Create(primeBitLength, compatibilityFlags, randomNumberGenerator, CandidatePCallback);

					// The pre-primality-check callback for determining a suitable 'q' prime requires knowing 'p'
					bool qCallback(BigInteger candidateQ, int bitLength)
					{
						return CandidateQCallback(candidateQ, prime1.Value, primeBitLength);
					}
					// Second, search for a suitable prime for 'q', passing the pre-primality-check callback
					BigPrime prime2 = BigPrime.Create(primeBitLength, compatibilityFlags, randomNumberGenerator, qCallback);

					// PyCryptodome's outer loop in Crypto.PublicKey.RSA:
					//   * Rejects 'p' and 'q' if their product is not a modulus with the requested bit length
					//   * Swaps 'p' and 'q' if 'p > q' (we're using a SortedSet)
					if ((prime1.Value * prime2.Value).GetBitLength() == keyBitLength)
					{
						primes.Add(prime1);
						primes.Add(prime2);
					}
					else
					{
						continue;
					}
				}

				// Conduct tests that potential p and q are suitable for RSA
				rsaParameters = StandardRSA.GetRSAParametersForPrimes(primes.ElementAt(pIndex), primes.ElementAt(qIndex), keyBitLength);
			}

			// Return the RSAParameters
			return rsaParameters.Value;
		}
	}
}
