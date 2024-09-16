using System;
using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{
		/// <summary>
		/// Calculates the modular multiplicative inverse using the Extended Euclidian Algorithm.
		/// </summary>
		/// <remarks>
		/// <para>Reference: Implements the algorithm as described by the Wikipedia article <see href="https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm">Extended Euclidian algorithm</see>.</para>
		/// <para>Given the formula <c>ax ≡ 1 (mod b)</c>, where <c>a</c> is parameter <paramref name="a"/> and <c>b</c> is parameter <paramref name="b"/>,
		///  tries to calculate and return <c>x</c> by solving <c>x ≡ a^(-1) (mod b)</c>.</para>
		/// </remarks>
		/// <param name="a">The integer <c>a</c> for formula <c>ax ≡ 1 (mod b)</c>.</param>
		/// <param name="b">The integer <c>b</c> for formula <c>ax ≡ 1 (mod b)</c>.</param>
		/// <returns>The modular multiplicative inverse (the <c>x</c> in <c>ax ≡ 1 (mod b)</c>).</returns>
		/// <exception cref="ArgumentException">Thrown if <paramref name="a"/> and <paramref name="b"/> are not coprime.</exception>
		public static BigInteger ModInverse(this BigInteger a, BigInteger b)
		{
			// Note: Variable names are based on their value's meaning for the next iteration
			//  of the while loop because each iteration sets up the variables for the next one.

			// Set t for index 0 equal to 0 (we start at index 2)
			BigInteger tIndexMinus2 = 0;
			// Set t for index 1 equal to 1 (we start at index 2)
			BigInteger tIndexMinus1 = 1;
			// Make the first iteration's dividend equal to parameter 'b'
			BigInteger dividend = b;
			// Make the first iteration's divisor equal to parameter 'a'
			BigInteger divisor = a;

			// While the remainder (variable name: divisor) is not zero
			while (divisor != 0)
			{
				// Calculate the quotient and remainder for dividend/divisor
				(BigInteger quotient, BigInteger remainder) = BigInteger.DivRem(dividend, divisor);
				// Calculate t for this iteration
				BigInteger t = tIndexMinus2 - quotient * tIndexMinus1;
				// This iteration's divisor becomes the next iteration's dividend
				dividend = divisor;
				// This iteration's remainder becomes the next iteration's divisor
				divisor = remainder;
				// This iteration's tIndexMinus1 becomes the next iteration's tIndexMinus2
				tIndexMinus2 = tIndexMinus1;
				// This iteration's t becomes the next iteration's tIndexMinus1
				tIndexMinus1 = t;
			}

			// The Greatest Common Divisor was the remainder for the iteration prior to the iteration
			//  where the remainder was 0.
			// If the GCD (variable name: dividend) is not 1, a and b are not coprime.
			if (dividend != 1)
			{
				throw new ArgumentException("a and b must be coprime.");
			}

			// Return the modular multiplicative inverse
			return (tIndexMinus2 % b + b) % b;
		}
	}
}
