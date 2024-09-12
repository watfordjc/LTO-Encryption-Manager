using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{
		/// <summary>
		/// Determine if a BigInteger is a perfect square.
		/// </summary>
		/// <param name="number">The number to check.</param>
		/// <returns>(<c>true</c>, <see cref="BigInteger"/> <c>squareRoot</c>) if number is a perfect square, (<c>false</c>, <c>null</c>) if it is not.</returns>
		public static (bool, BigInteger?) IsPerfectSquare(BigInteger number)
		{
			// Negative numbers cannot be perfect squares
			if (number < 0)
			{
				return (false, null);
			}

			// 0 and 1 are perfect squares
			if (number == 0)
			{
				return (true, 0);
			}
			else if (number == 1)
			{
				return (true, 1);
			}

			// Calculate the square 'root'
			BigInteger root = NewtonPlusSquareRoot(number);
			// Square the calculated 'root'
			BigInteger rootSquared = root * root;
			// Compare the calculated 'rootSquared' result with 'number'
			int sign = BigInteger.Compare(rootSquared, number);
			// If the first result for 'rootSquared' is equal to 'number', assume the calculated square root is the square root
			if (sign == 0)
			{
				return (true, root);
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
			return rootSquared == number ? (true, root) : (false, null);
		}
	}
}
