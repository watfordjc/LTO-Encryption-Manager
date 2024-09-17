using System;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms
{
	public static partial class StandardRSA
	{
		/// <summary>
		/// Flags, and combinations of flags, used to change how deterministic prime number and asymmetric key generation is performed.
		/// </summary>
		/// <remarks>
		/// <para>Other implementations of BIP85, and their dependencies, may behave differently or change how they function.</para>
		/// <para>These compatibility flags should aid in the recreation of keys if an implementation loses backwards-compatibility.</para>
		/// </remarks>
		[Flags]
		public enum Compatibility
		{
			/// <summary>
			/// A 0 flag is required.
			/// </summary>
			None = 0,
			/// <summary>
			/// For RSA, Q will be greater than P.
			/// </summary>
			/// <remarks>
			/// <para>PyCryptodome behaviour.</para>
			/// </remarks>
			RSAPrimeQGreaterThanPrimeP = 1,
			/// <summary>
			/// All numbers coming out of the RNG will have the MSb forcefully set to 1.
			/// </summary>
			/// <remarks>
			/// <para>PyCryptodome and OpenSSL behaviour.</para>
			/// </remarks>
			SetMostSignificantBit = 2,
			/// <summary>
			/// All numbers coming out of the RNG will have the second-MSb forcefully set to 1.
			/// </summary>
			SetSecondMostSignificantBit = 4,
			/// <summary>
			/// Any numbers without the second-MSb set to 1 will be rejected.
			/// </summary>
			RequireSecondMostSignificantBit = 8,
			/// <summary>
			/// All numbers coming out of the RNG will have the LSb forcefully set to 1.
			/// </summary>
			/// <remarks>
			/// <para>PyCryptodome and OpenSSL behaviour.</para>
			/// </remarks>
			SetLeastSignificantBit = 16,
			/// <summary>
			/// The generation of prime numbers and witness numbers will use the RNG, and threading will be disabled.
			/// </summary>
			/// <remarks>
			/// <para>PyCryptodome behaviour since PyCryptodome v3.10.0.</para>
			/// </remarks>
			UseSuppliedRNGForPrimeWitnessNumbers = 32,
			/// <summary>
			/// PyCryptodome's number of Miller-Rabin rounds for an E-30 error level will be used.
			/// </summary>
			UsePyCryptodomeMillerRabinRounds = 64,
			/// <summary>
			/// The smallest number of bases will be used for Miller-Rabin, if there is a known set of bases that can be used for a deterministic test.
			/// </summary>
			UseDeterministicMillerRabinForSmallNumbers = 128,
			/// <summary>
			/// Deterministic Miller-Rabin will be performed for large numbers (very slow).
			/// </summary>
			UseDeterministicMillerRabinForLargeNumbers = 256,
			/// <summary>
			/// Miller-Rabin testing will be conducted.
			/// </summary>
			PerformMillerRabinTesting = 512,
			/// <summary>
			/// Lucas testing will be conducted.
			/// </summary>
			PerformLucasTesting = 1024,
			/// <summary>
			/// All Fermat numbers will be considered not-prime.
			/// </summary>
			RejectFermatNumbers = 2048,
			/// <summary>
			/// All Mersenne numbers will be considered not-prime.
			/// </summary>
			RejectMersenneNumbers = 4096,

			// Notes
			// -----
			// PyCryptodome compatibility flag combinations
			// Bugfix commits that didn't change the functionality of the maths were skipped over in my code comparisons

			// PyCryptodome version v3.20.0 looks like it has had no relevant changes since v3.10.0
			// 
			// Crypto.Math.Primality
			//   * Last bip85 breaking change was commit cb3f5dd639b88d91c3a55000715cf50b566bd504, 2021-01-04, first included in tag v3.10.0
			//     * Commit message states "miller_rabin_test() was not using the provided random source"
			//   * Previous real change was commit cd7f0128b6e5608911b82cecc0a0da19cdcb5db9, 2018-11-04, first included in tag v3.7.1x
			/// <summary>
			/// Flag combination for compatibility with PyCryptodome v3.10.0.
			/// </summary>
			PyCryptodomeVersion003010000 =
				RSAPrimeQGreaterThanPrimeP |
				SetMostSignificantBit |
				SetLeastSignificantBit |
				UseSuppliedRNGForPrimeWitnessNumbers |
				UsePyCryptodomeMillerRabinRounds |
				PerformMillerRabinTesting |
				PerformLucasTesting,

			// Crypto.Math._IntegerBase
			//   * No breaking changes since at least commit fa933ab29ec66151f0e6f937cf998e8c27bfa075, 2018-11-23, first included in tag v3.7.1x
			// Crypto.Math._IntergerGMP
			//   * Last real change was commit cd7f0128b6e5608911b82cecc0a0da19cdcb5db9, 2018-11,04, first included in tag v3.7.1x
			// Crypto.Random (see also: Crypto.Math.Primality)
			//   * Last real change was commit cd7f0128b6e5608911b82cecc0a0da19cdcb5db9, 2018-11-04, first included in tag v3.7.1x
			// Crypto.Math._IntegerNative
			//   * No breaking changes since at least commit 7b1249e71812f276926b27505524b9102a09f421, 2018-01-21, first included in tag v3.4.8x
			// Crypto.PublicKey.RSA.generate()
			//   * Last real change was commit 1f3c1b4fcc2b21fc2f5e5f1519c3bd2c1814efda, 2015-03-11, first included in tag v3.1
			/// <summary>
			/// Flag combination for compatibility with PyCryptodome v3.7.1x.
			/// </summary>
			PyCryptoDomeVersion003007000x =
				RSAPrimeQGreaterThanPrimeP |
				SetMostSignificantBit |
				SetLeastSignificantBit |
				UsePyCryptodomeMillerRabinRounds |
				PerformMillerRabinTesting |
				PerformLucasTesting,

			/// <summary>
			/// Flag combination for compatibility with the bip85 Python reference implementation at the time RSA key generation tests were added.
			/// </summary>
			/// <remarks>
			/// <para><see href="https://github.com/ethankosakovsky/bip85/commit/7892bbddc51f498d1a693cca3f6d642b75cb3373">GitHub/ethankosakovsky/bip85 commit 7892bbddc51f498d1a693cca3f6d642b75cb3373</see>, 2021-03-13, not yet in a tag/release.</para>
			/// </remarks>
			BIP85 = PyCryptodomeVersion003010000,

			/// <summary>
			/// Flag combination to reject primes that can be generated using well-known formulae, for being too weak.
			/// </summary>
			RejectWeakPrimes = RejectFermatNumbers |
				RejectMersenneNumbers,

			/// <summary>
			/// Flag combination if BIP85 compatibility is not required.
			/// </summary>
			/// <remarks>
			/// <para>WARNING: This flag combination has not yet been finalised and is subject to breaking changes.</para>
			/// </remarks>
			Default = UsePyCryptodomeMillerRabinRounds |
				//UseDeterministicMillerRabinForSmallNumbers |
				PerformMillerRabinTesting |
				PerformLucasTesting |
				RejectWeakPrimes
		}
	}
}
