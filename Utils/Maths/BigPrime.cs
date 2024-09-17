using System;
using System.Collections.ObjectModel;
using System.Numerics;
using System.Security.Cryptography;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Algorithms;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths
{
	/// <summary>
	/// A wrapper class for a <see cref="BigInteger"/> object (referenced in <see cref="BigPrime.Value"/>) that extends <see cref="BigInteger"/>
	///  with additional properties related to primality testing.
	/// </summary>
	public partial class BigPrime : IComparable<BigPrime>, IComparable<BigInteger>
	{
		/// <summary>
		/// The first 100 prime numbers.
		/// </summary>
		public static readonly Collection<uint> First100Primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541];

		/// <summary>
		/// A random <see cref="int"/> (per thread) that is combined with <see cref="Value"/>'s hash code in <see cref="GetHashCode"/>.
		/// </summary>
		/// <remarks>
		/// <para><see cref="BigInteger.GetHashCode"/> returns the same value (per thread?) for all <see cref="BigInteger"/> objects that have identical values.</para>
		/// <para><see cref="BigPrime"/> objects have properties based entirely on the mathematical properties of the value of <see cref="Value"/>.</para>
		/// <para>By combining this 'prefix' with the hash code for <see cref="Value"/>, all <see cref="BigPrime"/> objects with identical underlying
		///  <see cref="BigInteger"/>s will have identical (per thread) <see cref="GetHashCode"/> return values.</para>
		/// </remarks>
		private static readonly int hashCodePrefix = RandomNumberGenerator.GetInt32(int.MinValue, int.MaxValue);

		/// <summary>
		/// The underlying <see cref="BigInteger"/> of this <see cref="BigPrime"/>.
		/// </summary>
		public BigInteger Value { get; private set; }

		/// <inheritdoc cref="BigInteger.IsEven"/>
		public bool IsEven => Value.IsEven;

		/// <summary>
		/// Indicates whether the value of the current <see cref="BigPrime.Value"/> property is an odd number.
		/// </summary>
		/// <returns>
		/// <see langword="true"/> if the value of the <see cref="BigPrime.Value"/> property is an odd number; otherwise, <see langword="false"/>.
		/// </returns>
		public bool IsOdd => !Value.IsEven;

		/// <inheritdoc cref="BigInteger.IsZero"/>
		public bool IsZero => Value.IsZero;

		/// <inheritdoc cref="BigInteger.IsOne"/>
		public bool IsOne => Value.IsOne;

		/// <inheritdoc cref="BigInteger.IsPowerOfTwo"/>
		public bool IsPowerOfTwo => Value.IsPowerOfTwo;

		/// <inheritdoc cref="BigInteger.GetBitLength"/>
		public long BitLength => Value.GetBitLength();

		/// <inheritdoc cref="BigInteger.GetByteCount(bool)"/>
		public int UnsignedByteCount => Value.GetByteCount(true);

		/// <inheritdoc cref="BigInteger.GetByteCount(bool)"/>
		public int SignedByteCount => Value.GetByteCount(false);

		bool? _isPerfectSquare;
		/// <summary>
		/// Indicates whether the value of the <see cref="BigPrime.Value"/> property is a perfect square.
		/// </summary>
		/// <returns>
		/// <see langword="true"/> if the value of the <see cref="BigPrime.Value"/> property is a perfect square; otherwise, <see langword="false"/>.
		/// </returns>
		public bool IsPerfectSquare
		{
			get
			{
				_isPerfectSquare ??= CheckPerfectSquare();
				return _isPerfectSquare.GetValueOrDefault(false);
			}
		}

		/// <summary>
		/// Indicates whether a factor has been found for the value of the <see cref="BigPrime.Value"/> property.
		/// </summary>
		/// <returns>
		/// <see langword="true"/> if a factor has been found for value of the <see cref="BigPrime.Value"/> property; otherwise, <see langword="null"/>.
		/// </returns>
		public bool? HasFactor { get; private set; }

		bool? _isSmallPrime;
		/// <summary>
		/// Indicates whether the value of the <see cref="BigPrime.Value"/> property is a small prime.
		/// </summary>
		/// <returns>
		/// <see langword="true"/> if the value of the <see cref="BigPrime.Value"/> property is contained in <see cref="BigPrime.First100Primes"/>;
		///  otherwise, <see langword="false"/>.
		/// </returns>
		public bool IsSmallPrime
		{
			get
			{
				_isSmallPrime ??= CheckSmallPrime();
				return _isSmallPrime.GetValueOrDefault(false);
			}
		}

		bool? _isFermatNumber;
		/// <summary>
		/// Indicates whether the value of the <see cref="Value"/> property is a Fermat number.
		/// </summary>
		/// <remarks>
		/// <para>Note: This property does not indicate Fermat primes.</para>
		/// </remarks>
		public bool IsFermatNumber
		{
			get
			{
				_isFermatNumber ??= Value.IsFermatNumber();
				return _isFermatNumber.GetValueOrDefault(false);
			}
		}

		bool? _isMersenneNumber;
		/// <summary>
		/// Indicates whether the value of the <see cref="Value"/> property is a Mersenne number.
		/// </summary>
		/// <remarks>
		/// <para>Note: This property does not indicate Mersenne primes.</para>
		/// </remarks>
		public bool IsMersenneNumber
		{
			get
			{
				_isMersenneNumber ??= Value.IsMersenneNumber();
				return _isMersenneNumber.GetValueOrDefault(false);
			}
		}

		/// <summary>
		/// Indicates whether the value of the <see cref="Value"/> property is possibly a weak prime.
		/// </summary>
		/// <returns>
		/// <para><see langword="true"/> if any of the following are true:
		///   <see cref="IsSmallPrime"/>,
		///   <see cref="IsFermatNumber"/>,
		///   <see cref="IsMersenneNumber"/>; otherwise <see langword="false"/>.</para>
		/// </returns>
		/// <remarks>
		/// <para>Note: This property does not indicate primality.</para>
		/// </remarks>
		public bool IsPossiblyWeakPrime => IsSmallPrime || IsFermatNumber || IsMersenneNumber;

		bool? _isProbablePrime;
		/// <summary>
		/// Indicates whether the value of the <see cref="BigPrime.Value"/> property is probably prime.
		/// </summary>
		/// <returns>
		/// <para><see langword="true"/> if the value of the <see cref="BigPrime.Value"/> property is probably prime or definitely prime.</para>
		/// <para><see langword="false"/> if it is likely composite or definitely compositie.</para>
		/// <para><see langword="null"/> if it has not yet been determined.</para>
		/// </returns>
		/// <remarks>
		/// <para>This property returns <see langword="null"/> if <see cref="CompatibilityFlags"/> did not include any primality testing flags when
		/// the current <see cref="BigPrime"/> object was created and <see cref="CheckPrimality(StandardRSA.Compatibility?, RandomNumberGenerator?, int?)"/>
		///  has not been called with a <see cref="StandardRSA.Compatibility"/> containing primality testing flags.</para>
		/// </remarks>
		public bool? IsProbablePrime
		{
			get
			{
				if (IsSmallPrime)
				{
					return true;
				}
				else if (HasFactor == null && _isProbablePrime == null)
				{
					return null;
				}
				else
				{
					return !HasFactor.GetValueOrDefault(false) && _isProbablePrime.GetValueOrDefault(false);
				}
			}
		}

		/// <summary>
		/// Flags that indicated, at the time the current <see cref="BigPrime"/> object was created, how primality and other tests should be conducted
		///  on the value of the <see cref="BigPrime.Value"/> property.
		/// </summary>
		public StandardRSA.Compatibility CompatibilityFlags { get; private set; }

		/// <inheritdoc cref="BigPrime.BigPrime(BigInteger, StandardRSA.Compatibility)"/>
		public BigPrime(byte number, StandardRSA.Compatibility compatibilityFlags)
		{
			Initialise(number, compatibilityFlags);
		}

		/// <inheritdoc cref="BigPrime.BigPrime(BigInteger, StandardRSA.Compatibility)"/>
		public BigPrime(ushort number, StandardRSA.Compatibility compatibilityFlags)
		{
			Initialise(number, compatibilityFlags);
		}

		/// <inheritdoc cref="BigPrime.BigPrime(BigInteger, StandardRSA.Compatibility)"/>
		public BigPrime(uint number, StandardRSA.Compatibility compatibilityFlags)
		{
			Initialise(number, compatibilityFlags);
		}

		/// <inheritdoc cref="BigPrime.BigPrime(BigInteger, StandardRSA.Compatibility)"/>
		public BigPrime(ulong number, StandardRSA.Compatibility compatibilityFlags)
		{
			Initialise(number, compatibilityFlags);
		}

		/// <summary>
		/// Create a new <see cref="BigPrime"/> object based on <paramref name="number"/>.
		/// </summary>
		/// <param name="number">The number that will be referenced by <see cref="BigPrime.Value"/>.</param>
		/// <param name="compatibilityFlags">Flags that indicate how primality and other tests should be conducted on the <see cref="BigPrime"/> object.</param>
		public BigPrime(BigInteger number, StandardRSA.Compatibility compatibilityFlags)
		{
			Initialise(number, compatibilityFlags);
		}

		private void Initialise(BigInteger number, StandardRSA.Compatibility compatibilityFlags)
		{
			Value = number;
			CompatibilityFlags = compatibilityFlags;
			if (IsEven && number > 2)
			{
				HasFactor = true;
			}
		}

		private bool CheckSmallPrime()
		{
			return BigPrime.First100Primes.Count > 0 &&
				Value <= BigPrime.First100Primes[^1] &&
				BigPrime.First100Primes.Contains((uint)Value);
		}

		private bool CheckPerfectSquare()
		{
			return Value.IsPerfectSquare();
		}

		/// <summary>
		/// Checks whether <paramref name="factor"/> can be used to determine if
		///  <see cref="HasFactor"/> should be <see langword="true"/>.
		/// </summary>
		/// <param name="factor">A possible factor of <see cref="Value"/>.</param>
		/// <remarks>
		/// <para>If <see cref="HasFactor"/> is already <see langword="true"/>, this method
		///  does nothing.</para>
		/// <para>If the GCD of <see cref="Value"/> and <paramref name="factor"/> is not 1,
		///  <see cref="HasFactor"/> will be set to <see langword="true"/>.</para>
		/// <para>If the GCD of <see cref="Value"/> and <paramref name="factor"/> is 1,
		///  <see cref="HasFactor"/> will be set to <see langword="true"/> if <see cref="Value"/>
		///  is wholly divisible by <paramref name="factor"/> with a quotient greater than 1.</para>
		///  </remarks>
		public void CheckFactor(BigInteger factor)
		{
			if (HasFactor.GetValueOrDefault(false))
			{
				return;
			}
			BigInteger gcd = BigInteger.GreatestCommonDivisor(factor, Value);
			if (gcd != 1)
			{
				HasFactor = true;
				return;
			}
			(BigInteger quotient, BigInteger remainder) = BigInteger.DivRem(Value, factor);
			if (remainder == 0 && quotient > 1)
			{
				HasFactor = true;
			}
		}

		/// <inheritdoc cref="BigInteger.CompareTo(BigInteger)"/>
		public int CompareTo(BigPrime? other)
		{
			return Value.CompareTo(other?.Value);
		}

		/// <inheritdoc cref="object.Equals(object?)"/>
		public override bool Equals(object? obj)
		{
			if (ReferenceEquals(this, obj))
			{
				return true;
			}
			else if (obj is null)
			{
				return false;
			}
			else
			{
				return obj is BigPrime && Value.Equals((obj as BigPrime)?.Value);
			}
		}

		/// <summary>
		/// Returns the hash code for the current <see cref="BigPrime"/> object.
		/// </summary>
		/// <returns>A 32-bit signed integer hash code.</returns>
		public override int GetHashCode()
		{
			return HashCode.Combine(hashCodePrefix, Value.GetHashCode());
		}

		/// <inheritdoc cref = "BigInteger.CompareTo(BigInteger)" />
		public int CompareTo(BigInteger other)
		{
			return Value.CompareTo(other);
		}

		/// <summary>Defines an implicit conversion of a <see cref="BigPrime"/> to a <see cref="BigInteger"/>.</summary>
		/// <param name="value">The value to convert to a <see cref="BigInteger"/>.</param>
		/// <returns>An object that contains the value of the value parameter.</returns>
		public static implicit operator BigInteger(BigPrime value)
		{
			ArgumentNullException.ThrowIfNull(value);
			return value.Value;
		}

		/// <summary>
		/// Gets the <see cref="BigInteger"/> object this <see cref="BigPrime"/> object references.
		/// </summary>
		/// <returns>The current <see cref="BigPrime"/> object's underlying <see cref="BigInteger"/> object (the <see cref="Value"/> property).</returns>
		public BigInteger ToBigInteger()
		{
			return Value;
		}

		/// <inheritdoc cref="BigInteger.ToByteArray()"/>
		public byte[] ToByteArray()
		{
			return Value.ToByteArray();
		}

		/// <inheritdoc cref="BigInteger.ToByteArray(bool, bool)"/>
		public byte[] ToByteArray(bool isUnsigned = false, bool isBigEndian = false)
		{
			return Value.ToByteArray(isUnsigned, isBigEndian);
		}

		/// <inheritdoc cref="BigInteger.operator==(BigInteger, BigInteger)"/>
		public static bool operator ==(BigPrime left, BigPrime right)
		{
			if (Equals(left?.Value, null))
			{
				return Equals(right?.Value, null);
			}

			return left.Value.Equals(right?.Value);
		}

		/// <inheritdoc cref="BigInteger.operator!=(BigInteger, BigInteger)"/>
		public static bool operator !=(BigPrime left, BigPrime right)
		{
			return !(left == right);
		}

		/// <inheritdoc cref="BigInteger.operator&lt;(BigInteger, BigInteger)"/>
		public static bool operator <(BigPrime left, BigPrime right)
		{
			return left is null ? right is not null : left.CompareTo(right) < 0;
		}

		/// <inheritdoc cref="BigInteger.operator&lt;=(BigInteger, BigInteger)"/>
		public static bool operator <=(BigPrime left, BigPrime right)
		{
			return left is null || left.CompareTo(right) <= 0;
		}

		/// <inheritdoc cref="BigInteger.operator&gt;(BigInteger, BigInteger)"/>
		public static bool operator >(BigPrime left, BigPrime right)
		{
			return left is not null && left.CompareTo(right) > 0;
		}

		/// <inheritdoc cref="BigInteger.operator&gt;=(BigInteger, BigInteger)"/>
		public static bool operator >=(BigPrime left, BigPrime right)
		{
			return left is null ? right is null : left.CompareTo(right) >= 0;
		}

		/// <inheritdoc cref="BigInteger.operator*(BigInteger, BigInteger)"/>
		public static BigInteger operator *(BigPrime left, BigInteger right)
		{
			return Multiply(left, right);
		}

		/// <inheritdoc cref="BigInteger.Multiply(BigInteger, BigInteger)"/>
		public static BigInteger Multiply(BigPrime left, BigInteger right)
		{
			ArgumentNullException.ThrowIfNull(left);
			ArgumentNullException.ThrowIfNull(right);
			return left.Value * right;
		}

		/// <inheritdoc cref="BigInteger.operator+(BigInteger, BigInteger)"/>
		public static BigInteger operator +(BigPrime left, BigInteger right)
		{
			return Add(left, right);
		}

		/// <inheritdoc cref="BigInteger.Add(BigInteger, BigInteger)"/>
		public static BigInteger Add(BigPrime left, BigInteger right)
		{
			ArgumentNullException.ThrowIfNull(left);
			ArgumentNullException.ThrowIfNull(right);
			return left.Value + right;
		}

		/// <inheritdoc cref="BigInteger.operator-(BigInteger, BigInteger)"/>
		public static BigInteger operator -(BigPrime left, BigInteger right)
		{
			return Subtract(left, right);
		}

		/// <inheritdoc cref="BigInteger.Subtract(BigInteger, BigInteger)"/>
		public static BigInteger Subtract(BigPrime left, BigInteger right)
		{
			ArgumentNullException.ThrowIfNull(left);
			ArgumentNullException.ThrowIfNull(right);
			return left.Value - right;
		}
	}
}
