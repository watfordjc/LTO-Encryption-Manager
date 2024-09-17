using System;
using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths.PrimalityTests
{
	/// <summary>
	/// <para>Provides static methods for determining primality using the Lucas-Lehmer primality test.</para>
	/// </summary>
	public static class Lucas
	{
		/// <summary>
		/// Tests primality of <paramref name="number"/> using the Lucas-Lehmer primality test.
		/// </summary>
		/// <param name="number">The number to be primality tested (also known as <c>C</c>).</param>
		/// <remarks>
		/// <para>Reference: <em>Lucas Probabilistic Primality Test</em>, C.3.3,
		///  <xref href="doi:10.6028/NIST.FIPS.186-5">
		///   <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf"><em>FIPS 186-5</em></see>
		///  </xref>
		///  by NIST.</para>
		/// <para>If <see cref="BigPrime.IsSmallPrime"/> is <see langword="true"/> for <paramref name="number"/>, <see langword="true"/> is returned.</para>
		/// <para>If <see cref="BigPrime.IsEven"/> or <see cref="BigPrime.IsPerfectSquare"/> is <see langword="true"/> for <paramref name="number"/>, <see langword="false"/> is returned.</para>
		/// </remarks>
		/// <returns>
		///  <para><see langword="true"/> if <paramref name="number"/> is probably prime.</para>
		///  <para><see langword="false"/> if <paramref name="number"/> is likely composite or definitely composite.</para>
		/// </returns>
		public static bool IsProbablePrime(BigPrime number)
		{
			ArgumentNullException.ThrowIfNull(number);

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
			// Step 1: Check if a perfect square
			if (number.IsPerfectSquare)
			{
				return false;
			}

			// Step 2: Find the first D (Jacobi sequence number) where the Jacobi symbol for (D, C) is -1
			// Store the value of -n for comparisons whilst searching for the Jacobi symbol
			BigInteger negativeNumber = BigInteger.Negate(number.Value);
			// Set the initial Jacobi sequence number to null
			BigInteger? d = null;
			// Initialise the Jacobi symbol to 0
			int jacobiSymbol = 0;
			// Find the first D (Jacobi sequence number) where the Jacobi symbol is -1
			while (d == null || jacobiSymbol != -1)
			{
				// Get the next Jacobi sequence number
				d = JacobiSequence.GetNextValue(d);
				// Skip to next iteration if the absolute value of 'd' equals 'number' (n, n) and (n, -n) is always 0
				if (d == number.Value || d == negativeNumber)
				{
					continue;
				}
				// Get the Jacobi symbol for (d, n)
				jacobiSymbol = Jacobi.GetSymbol(d.Value, number.Value);
				// Check if 'number' is composite.
				if (jacobiSymbol == 0)
				{
					return false;
				}
			}

			// Step 3
			BigInteger k = number.Value + 1;
			//ReadOnlySpan<char> kString = (number + 1).ToString("B", CultureInfo.InvariantCulture);
			//Trace.WriteLine(kString.ToString());
			// Step 4
			int r = (int)k.GetBitLength() - 1;
			// Create a bitmask for all bits except the MSb
			BigInteger notMSbBitmask = ~(BigInteger.One << r);
			// Remove the MSb as we don't need it and to make getting the 2nd-MSb simpler
			k &= notMSbBitmask;
			// Right shift the bitmask
			notMSbBitmask >>>= 1;
			// Step 5
			BigInteger u = 1;
			BigInteger v = 1;
			// Step 6
			// Iterate i, 'For i = r–1 to 0' (i.e. r iterations, with i aligned to the value needed for bit shifts and masks)
			for (int i = r - 1; i >= 0; i--)
			{
				// Step 4 - get the 2nd-MSb (the MSb has been removed)
				BigInteger k2ndMSb = k >>> i;
				// Step 6.1: uTemp = v * v % number
				BigInteger uTemp = u * v;
				uTemp %= number.Value;
				// Step 6.2: vTemp = ((v * v) + ((u * u) * d) + number) / 2 % number
				BigInteger vTemp = v * v;
				vTemp += u * u * d.Value;
				if (!vTemp.IsEven)
				{
					vTemp += number.Value;
				}
				vTemp >>= 1;
				vTemp %= number.Value;
				// Step 6.3
				if (k2ndMSb == 1)
				{
					// Step 6.3.1: u = (u + v + number) / 2 % number
					u = uTemp + vTemp;
					if (!u.IsEven)
					{
						u += number.Value;
					}
					u >>= 1;
					u %= number.Value;
					// Step 6.3.2: v = ((d * uTemp) + vTemp + number) / 2 % number;
					v = uTemp * d.Value;
					v += vTemp;
					if (!v.IsEven)
					{
						v += number.Value;
					}
					v >>= 1;
					v %= number.Value;
				}
				else
				{
					// Step 6.3.3
					u = uTemp;
					// Step 6.3.4
					v = vTemp;
				}
				// Remove the 2nd-MSb (the MSb has already been removed)
				k &= notMSbBitmask;
				// Right shift the bitmask
				notMSbBitmask >>>= 1;
			}

			// Step 7
			if (u == 0)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
	}
}
