using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{

		/// <summary>
		/// Calculates whether a <paramref name="number"/> is a perfect square.
		/// </summary>
		/// <param name="number">The number to check.</param>
		/// <returns><see langword="true"/> if <paramref name="number"/> is a perfect square; otherwise <see langword="false"/>.</returns>
		public static bool IsPerfectSquare(this BigInteger number)
		{
			// Negative numbers cannot be perfect squares
			if (number < 0)
			{
				return false;
			}

			// 0 and 1 are perfect squares
			if (number == 0 || number == 1)
			{
				return true;
			}

			// Calculate the square 'root'
			BigInteger root = SquareRoot(number);
			// Square the calculated 'root'
			BigInteger rootSquared = root * root;
			// Compare the calculated 'rootSquared' result with 'number'
			int sign = BigInteger.Compare(rootSquared, number);
			// If the first result for 'rootSquared' is equal to 'number', assume the calculated square root is the square root
			if (sign == 0)
			{
				return true;
			}
			// If the first result for 'rootSquared' is less than 'number', increase 'root' until its square is not less than 'number'
			else if (sign < 0)
			{
				// Loop ends if 'rootSquared' becomes equal to 'number' or overshoots
				while (rootSquared < number)
				{
					root++;
					rootSquared = root * root;
				}
			}
			// If the first result for 'rootSquared' is more than 'number', decrease 'root' until its square is not more than 'number'
			else if (sign > 0)
			{
				// Loop ends if 'rootSquared' becomes equal to 'number' or overshoots
				while (rootSquared > number)
				{
					root--;
					rootSquared = root * root;
				}
			}

			// Assume the final result for 'rootSquared' is the square root if it is equal to 'number', otherwise assume 'number' is not a perfect square
			return rootSquared == number;
		}
	}
}
