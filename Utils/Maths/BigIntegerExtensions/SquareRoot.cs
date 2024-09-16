using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{
		/// <summary>
		/// Calculates the integer square root of a <paramref name="number"/>.
		/// </summary>
		/// <param name="number">The number to calculate the square root of.</param>
		/// <returns>The integer square root.</returns>
		public static BigInteger SquareRoot(this BigInteger number)
		{
			return NewtonPlusSquareRoot(number);
		}
	}
}
