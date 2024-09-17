using System.Numerics;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	/// <summary>
	/// <para>Provides static methods for calculating Jacobi sequence numbers (Jacobi symbol numerators) for Lucas testing.</para>
	/// </summary>
	/// <remarks>
	/// <para>The sequence {5, -7, 9, -11, 13, -15, ...} used for Jacobi symbol numerators in Lucas testing is identical to OEIS sequence number
	///  <see href="https://oeis.org/A157142">A157142</see>, <em>Signed denominators of Leibniz series for Pi/4</em>, offset by 2.</para>
	/// </remarks>
	public static class JacobiSequence
	{
		/// <summary>
		/// Returns the next Jacobi sequence number when given its preceding number in the sequence.
		/// </summary>
		/// <param name="sequenceNumber">The Jacobi sequence number preceding the return value,
		///  or <see langword="null"/> to return the first number in the sequence.</param>
		/// <returns>The Jacobi sequence number following <paramref name="sequenceNumber"/> in
		///  the sequence, or 5 if <paramref name="sequenceNumber"/> is <see langword="null"/>.</returns>
		/// <remarks>
		/// <para>Reference: <em>Jacobi Symbol Algorithm</em>, C.5,
		///  <xref href="doi:10.6028/NIST.FIPS.186-5">
		///   <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf"><em>FIPS 186-5</em></see>
		///  </xref>
		///  by NIST.</para>
		/// </remarks>
		public static BigInteger GetNextValue(BigInteger? sequenceNumber)
		{
			// Start sequence at 5
			if (sequenceNumber is null)
			{
				return 5;
			}
			// If the previous number was positive, increase by two, if negative decrease by 2
			sequenceNumber = BigInteger.IsPositive(sequenceNumber.Value) ? sequenceNumber += 2 : sequenceNumber -= 2;
			// If the previous number was positive/negative return as negative/postive
			return BigInteger.Negate(sequenceNumber.Value);
		}
	}
}
