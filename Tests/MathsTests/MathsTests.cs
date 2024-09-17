using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Numerics;
using uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Maths;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Tests.MathsTests
{
	[TestClass]
    public partial class MathsTests
    {
		[TestMethod]
		public void JacobiSequenceNumbersTest()
		{
			BigInteger[] expectedSequenceNumber = [5, -7, 9, -11, 13, -15, 17, -19, 21, -23, 25, -27, 29, -31];
			BigInteger[] sequenceNumber = new BigInteger[expectedSequenceNumber.Length];
			BigInteger? currentSequenceNumber = null;
			for (int i = 0; i < expectedSequenceNumber.Length; i++)
			{
				currentSequenceNumber = JacobiSequence.GetNextValue(currentSequenceNumber);
				sequenceNumber[i] = currentSequenceNumber.Value;
			}
			Assert.IsTrue(sequenceNumber.SequenceEqual(expectedSequenceNumber));
		}

		[TestMethod]
		public void JacobiSymbolTest()
		{
			uint[] numerators = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
			int[] denominator5 = [1, -1, -1, 1, 0, 1, -1, -1, 1, 0, 1, -1, -1, 1, 0, 1, -1, -1, 1, 0, 1, -1, -1, 1, 0, 1, -1, -1, 1, 0];
			int[] denominator7 = [1, 1, -1, 1, -1, -1, 0, 1, 1, -1, 1, -1, -1, 0, 1, 1, -1, 1, -1, -1, 0, 1, 1, -1, 1, -1, -1, 0, 1, 1];
			int[] denominator9 = [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0];
			int[] denominator11 = [1, -1, 1, 1, 1, -1, -1, -1, 1, -1, 0, 1, -1, 1, 1, 1, -1, -1, -1, 1, -1, 0, 1, -1, 1, 1, 1, -1, -1, -1];
			int[] denominator13 = [1, -1, 1, 1, -1, -1, -1, -1, 1, 1, -1, 1, 0, 1, -1, 1, 1, -1, -1, -1, -1, 1, 1, -1, 1, 0, 1, -1, 1, 1];
			Assert.AreEqual(numerators.Length, denominator5.Length);
			Assert.AreEqual(numerators.Length, denominator7.Length);
			Assert.AreEqual(numerators.Length, denominator9.Length);
			Assert.AreEqual(numerators.Length, denominator11.Length);
			Assert.AreEqual(numerators.Length, denominator13.Length);

			Assert.AreEqual(-1, Jacobi.GetSymbol(5, 3439601197));

			for (int i = 0; i < numerators.Length; i++)
			{
				Assert.AreEqual(denominator5[i], Jacobi.GetSymbol(numerators[i], 5));
				Assert.AreEqual(denominator7[i], Jacobi.GetSymbol(numerators[i], 7));
				Assert.AreEqual(denominator9[i], Jacobi.GetSymbol(numerators[i], 9));
				Assert.AreEqual(denominator11[i], Jacobi.GetSymbol(numerators[i], 11));
				Assert.AreEqual(denominator13[i], Jacobi.GetSymbol(numerators[i], 13));
			}
		}
    }
}
