using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	public static partial class StandardRSA
	{
		/// <summary>
		/// Callback function for RSA parameter 'q' candidates before they are put through primality testing.
		/// </summary>
		/// <param name="candidateQ">A number (not primality tested) that is a candidate for RSA parameter 'q'.</param>
		/// <param name="candidateP">A primality-tested candidate for RSA parameter 'p'.</param>
		/// <param name="primeBitLength">The required bit length of candidate numbers.</param>
		/// <returns><see langword="true"/> if the candidate should be primality tested; otherwise, <see langword="false"/>.</returns>
		/// <remarks>
		/// <para>Implements the callback function for 'q' in PyCryptodome's Crypto.PublicKey.RSA.</para>
		/// </remarks>
		public static bool CandidateQCallback(BigInteger candidateQ, BigInteger candidateP, int primeBitLength)
		{
			if (!CandidatePCallback(candidateQ, primeBitLength))
			{
				return false;
			}
			// Minimum distance definitions:
			// Wikipedia: 2n^(1/4), where n is p * q
			// PyCryptodome: `Integer(1) << (bits // 2 - 100)`, where bits is the modulus length in bits
			// OpenSSL: `(nbits >> 1) - 100`, where nbits is the modulus length in bits
			BigInteger minimumDistance = BigInteger.One << (primeBitLength - 100);
			// P and Q must be more than the minimum distance from each other (OpenSSL and PyCryptodome use `subtraction > distance = good`)
			if (BigInteger.Abs(candidateQ - candidateP) <= minimumDistance)
			{
				return false;
			}
			return true;
		}
	}
}
