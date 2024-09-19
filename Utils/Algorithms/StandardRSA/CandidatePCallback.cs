using System.Numerics;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	public static partial class StandardRSA
	{
		/// <summary>
		/// Callback function for RSA parameter 'p' candidates before they are put through primality testing.
		/// </summary>
		/// <param name="candidateP">A number (not primality tested) that is a candidate for RSA parameter 'p'.</param>
		/// <param name="primeBitLength">The required bit length of candidate numbers.</param>
		/// <returns><see langword="true"/> if the candidate should be primality tested; otherwise, <see langword="false"/>.</returns>
		/// <remarks>
		/// <para>Implements the callback function for 'p' (and in part for 'q'), in PyCryptodome's Crypto.PublicKey.RSA.</para>
		/// </remarks>
		public static bool CandidatePCallback(BigInteger candidateP, int primeBitLength)
		{
			BigInteger minimumP = BigIntegerExtensions.SquareRoot(BigInteger.One << (2 * primeBitLength - 1));
			if (candidateP < minimumP)
			{
				return false;
			}
			BigInteger candidatePMinusOne = candidateP - 1;
			BigInteger e = new(StandardRSA.ParameterE);
			if (BigInteger.GreatestCommonDivisor(candidatePMinusOne, e) != BigInteger.One)
			{
				return false;
			}
			return true;
		}
	}
}
