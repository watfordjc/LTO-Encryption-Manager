using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{
		/// <summary>
		/// Checks if a given number is a Fermat number.
		/// </summary>
		/// <param name="number">The number to check.</param>
		/// <returns><see langword="true"/> if <paramref name="number"/> is a Fermat number; otherwise, <see langword="false"/>.</returns>
		/// <remarks>
		/// <para>See also: <seealso cref="TryGetFermatNumberForBitLength(int, out BigInteger?)"/>.</para>
		/// </remarks>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="number"/>'s bit length is less than 1
		///  or exceeds <see cref="int.MaxValue"/>.</exception>
		public static bool IsFermatNumber(this BigInteger number)
		{
			ArgumentOutOfRangeException.ThrowIfGreaterThan(number.GetBitLength(), int.MaxValue, nameof(number.GetBitLength));
			bool fermatNumberForBitLength = TryGetFermatNumberForBitLength((int)number.GetBitLength(), out BigInteger? fermatNumber);
			return fermatNumberForBitLength && number == fermatNumber;
		}

		/// <summary>
		/// Calculates a Fermat number that fits within <paramref name="bitLength"/> bits.
		/// </summary>
		/// <param name="bitLength">The bit length of the requested Fermat number.</param>
		/// <param name="fermatNumber">The calculated Fermat number, if one exists that is exactly <paramref name="bitLength"/> bits long.</param>
		/// <returns><see langword="true"/> if the calculated <paramref name="fermatNumber"/> is exactly <paramref name="bitLength"/> bits long, otherwise <see langword="false"/>.</returns>
		/// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="bitLength"/> is less than 1.</exception>
		public static bool TryGetFermatNumberForBitLength(int bitLength, [NotNullWhen(true)] out BigInteger? fermatNumber)
		{
			// Negative and zero bit lengths are invalid
			ArgumentOutOfRangeException.ThrowIfNegativeOrZero(bitLength, nameof(bitLength));

			// 0b0 (0) and 0b1 (1) are not Fermat numbers
			if (bitLength == 1)
			{
				fermatNumber = null;
				return false;
			}
			// 0b10 (2) is not a Fermat number, whilst 0b11 (3) is a Fermat number
			else if (bitLength == 2)
			{
				fermatNumber = new(3);
				return true;
			}

			// Calculate 2^(2^n)+1
			fermatNumber = 2;
			for (long i = bitLength; i > 1; i /= 2)
			{
				fermatNumber = BigInteger.Pow(fermatNumber.Value, 2);
			}
			fermatNumber += 1;

			// Only set the Fermat number and return true if the bit length is correct
			if (fermatNumber.Value.GetBitLength() != bitLength)
			{
				fermatNumber = null;
				return false;
			}
			else
			{
				return true;
			}
		}
	}
}
