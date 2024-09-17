using System;
using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	/// <summary>
	/// <para>Provides static methods for calculating the Jacobi symbol.</para>
	/// </summary>
	/// <remarks>
	/// <para>The Jacobi symbol is a generalization of the Legendre symbol, used to determine if a number is a quadratic residue modulo a prime.</para>
	/// <para>It is a useful tool in number theory and cryptography.</para>
	/// </remarks>
	public static class Jacobi
	{
		/// <summary>
		/// <para>Calculates the Jacobi symbol of a given numerator and denominator.</para>
		/// </summary>
		/// <param name="numerator">The numerator (also known as <c>a</c>). See also: <seealso cref="JacobiSequence.GetNextValue(BigInteger?)"/>.</param>
		/// <param name="denominator">The denominator (also known as <c>n</c>). Must be odd and positive.</param>
		/// <returns>
		/// <para>1 if the numerator is a quadratic residue modulo the denominator.</para>
		/// <para>-1 if the numerator is a quadratic non-residue modulo the denominator.</para>
		/// <para>0 if the numerator is 0 or the denominator is not prime.</para>
		/// </returns>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="denominator"/> is less than 0.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="denominator"/> is even.</exception>
		/// <remarks>
		/// <para>Reference: <em>Algorithm 5</em> from the paper
		///  <xref href="doi:10.12732/iejpam.v15i1.2">
		///   <see href="https://www.e.ijpam.eu/contents/articles/202101501002.pdf"><em>A New Improvement Of Jacobi Symbol Algorithm</em></see>
		///  </xref>
		///  by Anton Iliev, Nikolay Kyurkchiev, and Asen Rahnev. IEJPAM, Volume 15, No. 1 (2021).</para>
		/// </remarks>
		public static int GetSymbol(BigInteger numerator, BigInteger denominator)
		{
			// Jacobi symbols are undefined for a negative denominator
			ArgumentOutOfRangeException.ThrowIfLessThan(denominator, 0);
			// Jacobi symbols are undefined for an even denominator
			if (denominator.IsEven)
			{
				throw new ArgumentException($"{nameof(denominator)} must be odd.", nameof(denominator));
			}
			// The Jacobi symbol is 0 if the numerator is 0
			if (numerator == 0)
			{
				return 0;
			}

			// Initialise 'a' to the original numerator
			BigInteger a = numerator;
			// Initialise 'n' to the original denominator
			BigInteger n = denominator;
			// Initialise result 'j' (the Jacobi symbol) to 1
			int j = 1;

			// If 'a' is negative
			if (a < 0)
			{
				// Reverse the sign of 'j' if 'n = 3 (mod 8)' or 'n = 5 (mod 8)'
				if ((n & 3) == 3)
				{
					j = -j;
				}
				// Make 'a' positive
				a = -a;
			}
			// Repeat until 'a' or 'n' become 1 or 0
			while (true)
			{
				// Reduce 'a' until it is 0 or odd, break if 'a' becomes 1, otherwise reduce 'n' modulo reduced 'a'
				if (a > 0)
				{
					// Reduce 'a' until it is odd
					while (a.IsEven)
					{
						// Divide 'a' by 2
						a >>= 1;
						// Reverse the sign of 'j' if 'n = 3 (mod 8)' or 'n = 5 (mod 8)'
						BigInteger nMod8 = n & 7;
						if ((nMod8 == 3) || (nMod8 == 5))
						{
							j = -j;
						}
					}

					// When 'a' equals 1, the GCD of 'a' and 'n' is 1
					if (a == 1)
					{
						n = 1;
						break;
					}

					// Reverse the sign of 'j' if 'n = 3 (mod 4)' and 'a = 3 (mod 4)'
					BigInteger aMod4 = a & 3;
					BigInteger nMod4 = n & 3;
					if (aMod4 == 3 && nMod4 == 3)
					{
						j = -j;
					}

					// Reduce 'n' modulo 'a'
					n %= a;
				}
				// When 'a' equals 0, the Jacobi symbol is 0
				else
				{
					break;
				}

				// Reduce 'n' until it is 0 or odd, break if 'n' becomes 1, otherwise reduce 'a' modulo reduced 'n'
				if (n > 0)
				{
					// Reduce 'n' until it is odd
					while (n.IsEven)
					{
						n >>= 1;
						// Reverse the sign of 'j' if 'a = 3 (mod 8)' or 'a = 5 (mod 8)'
						BigInteger aMod8 = a & 7;
						if ((aMod8 == 3) || (aMod8 == 5))
						{
							j = -j;
						}
					}

					// When 'n' equals 1, the GCD of 'a' and 'n' is 1
					if (n == 1)
					{
						break;
					}

					// Reverse the sign of 'j' if 'n = 3 (mod 4)' and 'a = 3 (mod 4)'
					BigInteger nMod4 = n & 3;
					BigInteger aMod4 = a & 3;
					if (nMod4 == 3 && aMod4 == 3)
					{
						j = -j;
					}

					// Reduce 'a' modulo 'n'
					a %= n;
				}
				// When 'n' is 0, the GCD of 'a' and 'n' is 1
				else
				{
					n = a;
					break;
				}
			}

			// If 'n' is 1, the Jacobi symbol is 1
			// If 'a' is 1, the Jacobi symbol is 1 if 'n = 1 (mod 4)'
			// If 'a' is 1, the Jacobi symbol is -1 if 'n = 3 (mod 4)'
			if (n == 1)
			{
				return j;
			}
			// Otherwise, the Jacobi symbol is 0
			else
			{
				return 0;
			}
		}
	}
}
