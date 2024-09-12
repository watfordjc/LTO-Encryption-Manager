using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{
		/// <summary>
		/// Calculates if a number is a Mersenne number.
		/// </summary>
		/// <param name="number">The number to check.</param>
		/// <returns><c>true</c> if <paramref name="number"/> is a Mersenne number.</returns>
		public static bool IsMersenneNumber(BigInteger number)
		{
			// Mersenne numbers are greater than 0, and are one less than a power of two
			return number > 0 && (number + 1).IsPowerOfTwo;
		}
	}
}
