using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	public static partial class BigIntegerExtensions
	{
		/// <summary>
		/// Approximates the integer square root of a number using the Newton-Raphson method.
		/// </summary>
		/// <param name="n">The number to estimate the square root of.</param>
		/// <returns>The approximate integer square root.</returns>
		public static BigInteger ApproximateSquareRoot(BigInteger n)
		{
			BigInteger x = n / 2;
			for (long i = (n.GetBitLength() + 1) / 2; i > 0; i--)
			{
				BigInteger nextX = (x + n / x) / 2;
				if (nextX == x)
				{
					break;
				}
				x = nextX;
			}
			return x;
		}
	}
}
