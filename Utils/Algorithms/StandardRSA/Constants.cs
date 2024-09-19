namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	public static partial class StandardRSA
	{
		/// <summary>
		/// The RSA public exponent 'e', typically a Fermat prime.
		/// </summary>
		/// <remarks>
		/// <para>'e' must be greater than 1, less than 'lambda(N)', not be coprime with 'lambda(N)', and preferably have a low hamming weight.</para>
		/// <para>e=65537 is the most widely used for RSA today, and will always be less than 'lambda(N)' for RSA-384+ (RSAParameters requires a minimum bit length of 384 bits).</para></remarks>
		public const int ParameterE = 65537;
	}
}
