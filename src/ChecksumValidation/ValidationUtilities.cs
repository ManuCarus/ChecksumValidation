/*
   ChecksumValidation - validates german bank accounts (account number against bank code), 
                                  international bank accounts (IBAN and BIC),
                                  german identity cards, german passports, and credit cards.

   Copyright (c) 2012 Manu Carus (mailto:manu.carus@ethical-hacking.de)

   This program is free software; you can redistribute it and/or modify it under the terms of 
   the GNU General Public License as published by the Free Software Foundation; 
   either version 3 of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
   without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
   See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along with this program; 
   if not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections;
using System.Collections.Specialized;
using System.Configuration;
using System.Text;
using ChecksumValidation.BankAccountValidation;

namespace ChecksumValidation
{
    public sealed class ValidationUtilities
    {
        // constants
        private static char[] c0 = { '0' };

        // private members
        TraceManager traceManager;

        // ctor
        internal ValidationUtilities(TraceManager traceManager)
        {
            this.traceManager = traceManager;
        }

        // retrieve bank codes assigned to a given checksum code
        public static StringCollection FindBankCodesByChecksumCode(string checksumCode, bool firstBankCodeOnly, BankAccountValidator bankAccountValidator)
        {
            if ((checksumCode == null) || (checksumCode.Length == 0)) throw new ArgumentNullException("checksumCode", "parameter not set!");
            if (bankAccountValidator == null) throw new ArgumentNullException("bankAccountValidator", "parameter not set!");

            // load bank directory (only if not already loaded)
            bankAccountValidator.Load();

            Hashtable banks = bankAccountValidator.Banks;
            StringCollection foundBankCodes = new StringCollection();

            foreach (object entry in banks.Values)
            {
                if (entry.GetType() != typeof(Bank)) throw new Exception(String.Format("(checksum code {0}): type mismatch", checksumCode));
                Bank bank = (Bank)entry;

                if (bank.ChecksumCode.Equals(checksumCode))
                {
                    foundBankCodes.Add(bank.Blz);
                    if (firstBankCodeOnly) break;
                }
            }

            return foundBankCodes;
        }

        public static StringCollection FindBankCodesByChecksumCode(string checksumCode, bool firstBankCodeOnly, string bankDirectory, TraceManager traceManager)
        {
            if ((checksumCode == null) || (checksumCode.Length == 0)) throw new ArgumentNullException("checksumCode", "parameter not set!");
            if ((bankDirectory == null) || (bankDirectory.Length == 0)) throw new ArgumentNullException("bankDirectory", "parameter not set!");
            if (traceManager == null) throw new ArgumentNullException("traceManager", "parameter not set!");

            BankAccountValidator bankAccountValidator = new BankAccountValidator(traceManager, bankDirectory);
            return FindBankCodesByChecksumCode(checksumCode, firstBankCodeOnly, bankAccountValidator);
        }

        public static string FindFirstBankCodeByChecksumCode(string checksumCode, string bankDirectory, TraceManager traceManager)
        {
            if ((checksumCode == null) || (checksumCode.Length == 0)) throw new ArgumentNullException("checksumCode", "parameter not set!");
            if ((bankDirectory == null) || (bankDirectory.Length == 0)) throw new ArgumentNullException("bankDirectory", "parameter not set!");
            if (traceManager == null) throw new ArgumentNullException("traceManager", "parameter not set!");

            BankAccountValidator bankAccountValidator = new BankAccountValidator(traceManager, bankDirectory);
            StringCollection foundBankCodes = FindBankCodesByChecksumCode(checksumCode, true, bankAccountValidator);

            if ((foundBankCodes == null) || (foundBankCodes.Count == 0)) return null;
            else return foundBankCodes[0];
        }

        public static string FindFirstBankCodeByChecksumCode(string checksumCode, BankAccountValidator bankAccountValidator)
        {
            if ((checksumCode == null) || (checksumCode.Length == 0)) throw new ArgumentNullException("checksumCode", "parameter not set!");
            if (bankAccountValidator == null) throw new ArgumentNullException("bankAccountValidator", "parameter not set!");

            StringCollection foundBankCodes = FindBankCodesByChecksumCode(checksumCode, true, bankAccountValidator);

            if ((foundBankCodes == null) || (foundBankCodes.Count == 0)) return null;
            else return foundBankCodes[0];
        }

        // multiplies each digit in arrbytAccountDigits from left to right with each factor in arrbytWeighting from left to right
        internal void MultiplyCyclicFromLeftToRightDigitByDigit(byte[] accountDigits, byte[] weighting)
        {
            MultiplyCyclicFromLeftToRightDigitByDigit(accountDigits, weighting, 0); // start with the first digit
        }

        // multiplies each digit in accountDigits from left to right with each factor in weighting from left to right, and starts at given position
        internal void MultiplyCyclicFromLeftToRightDigitByDigit(byte[] accountDigits, byte[] weighting, int startPosition)
        {
            if ((startPosition < 0) || (startPosition >= accountDigits.Length)) throw new ChecksumException("argument:1101", String.Format("start position {0} is out of bounds", startPosition.ToString()));

            TraceWeightingFromLeftToRight(weighting, startPosition, accountDigits.Length);

            int weightingIndex = 0;
            for (int accountDigitsIndex = startPosition; accountDigitsIndex < accountDigits.Length; accountDigitsIndex++)
            {
                accountDigits[accountDigitsIndex] *= weighting[weightingIndex];
                weightingIndex = (byte)((weightingIndex + 1) % weighting.Length);
            }

            TraceTemporaryResult(accountDigits);
        }

        // multiplies each digit in accountDigits from right to left with each factor in weighting from left to right
        internal void MultiplyCyclicFromRightToLeftDigitByDigit(byte[] accountDigits, byte[] weighting)
        {
            TraceWeightingFromRightToLeft(weighting, accountDigits.Length);

            int weightingIndex = 0;
            for (int accountDigitsIndex = accountDigits.Length - 1; accountDigitsIndex >= 0; accountDigitsIndex--)
            {
                accountDigits[accountDigitsIndex] *= weighting[weightingIndex];
                weightingIndex = (byte)((weightingIndex + 1) % weighting.Length);
            }

            TraceTemporaryResult(accountDigits);
        }

        internal int AddAllValues(byte[] accountDigits)
        {
            int sum = 0;
            foreach (byte b in accountDigits) sum += b;
            
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("sum:            {0}", sum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVeryVerbose);
            
            return sum;
        }

        // computes cross sum for every digit in acountDigits
        internal void ComputeCrossSumForEachDigit(byte[] accountDigits)
        {
            for (int i = 0; i < accountDigits.Length; i++)
            {
                accountDigits[i] = ComputeCrossSum(accountDigits[i]);
            }

            TraceTemporaryResult(accountDigits);
        }

        // computes cross sum for a number
        internal byte ComputeCrossSum(byte number)
        {
            return ComputeCrossSum((int)number);
        }

        // computes cross sum for a number
        internal byte ComputeCrossSum(int number)
        {
            int temp = number;
            byte crossSum = 0;

            while (temp > 0)
            {
                crossSum += (byte)(temp % 10);
                temp /= 10;
            }

            return crossSum;
        }

        // adds all values in given byte array
        // adds weighting factor to each digit in accountDigits from right to left 
        internal void AddWeightFromRightToLeft(byte[] accountDigits, byte[] weighting)
        {
            int weightingIndex = 0;
            for (int intAccountDigitsIndex = accountDigits.Length - 1; intAccountDigitsIndex >= 0; intAccountDigitsIndex--)
            {
                accountDigits[intAccountDigitsIndex] += weighting[weightingIndex];
                weightingIndex = (byte)((weightingIndex + 1) % weighting.Length);
            }

            TraceTemporaryResult(accountDigits);
        }

        // divides every digit by the divisor and adds the remainders
        internal int AddRemainders(byte[] accountDigits, byte checksumDivisor)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            int sum = 0;
            for (int accountDigitsIndex = 0; accountDigitsIndex < accountDigits.Length; accountDigitsIndex++)
            {
                byte remainder = (byte)(accountDigits[accountDigitsIndex] % checksumDivisor);
                traceManager.TraceLine(String.Format("    temp sum:       {0} mod {1} = {2}", accountDigits[accountDigitsIndex].ToString(), checksumDivisor.ToString(), remainder.ToString()), TraceManager.VerboseMode.VeryVeryVerbose);
                sum += remainder;
            }

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("    sum:            {0}", sum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVeryVerbose);

            return sum;
        }

        // enumerates every digit and applies modulo
        internal void ApplyModuloToEachDigit(byte[] digits, byte modulo)
        {
            for (int i = 0; i < digits.Length; i++)
            {
                digits[i] = (byte)(digits[i] % modulo);
            }

            TraceTemporaryResult(digits);
        }

        // helper function: cuts each number down to its last digit
        internal void ConsiderLowestDigitOfEachByte(byte[] accountDigits)
        {
            for (int i = 0; i < accountDigits.Length; i++)
            {
                accountDigits[i] = (byte)(accountDigits[i] % 10);
            }

            TraceTemporaryResult(accountDigits);
        }

        // helper function: converts byte array into string, i.e. every digit into one character
        internal string GetStringOfByteArray(byte[] accountDigitsModified)
        {
            StringBuilder strByteArray = new StringBuilder(accountDigitsModified.Length);

            for (int i = 0; i < accountDigitsModified.Length; i++)
            {
                strByteArray.Append(accountDigitsModified[i]);
            }

            return strByteArray.ToString();
        }

        // helper function: adds each digit in arrbytAccountDigits from left to right with each number in weighting from left to right, and starts at given position
        internal void AddCyclicFromLeftToRightDigitByDigit(byte[] accountDigits, byte[] weighting, int startAtPosition)
        {
            int weightingIndex = 0;
            for (int accountDigitsIndex = startAtPosition; accountDigitsIndex < accountDigits.Length; accountDigitsIndex++)
            {
                traceManager.TraceLine(String.Format("                                           {0} + {1} = {2}", accountDigits[accountDigitsIndex].ToString(), weighting[weightingIndex].ToString(), (accountDigits[accountDigitsIndex] + weighting[weightingIndex]).ToString()), TraceManager.VerboseMode.VeryVeryVerbose);

                accountDigits[accountDigitsIndex] += weighting[weightingIndex];
                weightingIndex = (byte)((weightingIndex + 1) % weighting.Length);
            }

            TraceTemporaryResult(accountDigits);
        }

        // helper function: computes remainder for each single digit in arrbytAccountDigits
        internal void ComputeRemainderForEachDigit(byte[] accountDigits, byte divisor)
        {
            for (int i = 0; i < accountDigits.Length; i++)
            {
                accountDigits[i] = (byte)(accountDigits[i] % divisor);
            }

            TraceTemporaryResult(accountDigits);
        }

        // helper function transforms each digit from right to left by mapping to transformation array (row index varies from right to left, column index corresponds to digit value)
        internal void TransformDigitByDigitFromRightToLeft(byte[] accountDigits, byte[][] transformation)
        {
            int rowIndex = 0;

            for (int i = accountDigits.Length - 1; i >= 0; i--)
            {
                accountDigits[i] = transformation[rowIndex][accountDigits[i]];

                rowIndex++;
                if (rowIndex > 3) rowIndex = 0;
            }
        }

        // helper function: computes eser account (8 digits)
        internal void GetEserFor8DigitAccount(string blz, string account10Digits, out string eserAccount, out string eserLeftPart, out string eserMidPart, out string eserRightPart)
        {
            // validate rules
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);
            if (accountWithoutLeadingZeroes.Length != 8) throw new BankAccountValidation.BankException("argument:1102", String.Format("algorithm is not applicable because account without leading zeroes '{0}' does not contain exactly 8 digits", accountWithoutLeadingZeroes));

            eserLeftPart = blz.Substring(4);
            eserMidPart = accountWithoutLeadingZeroes.Substring(0, 2);
            eserRightPart = accountWithoutLeadingZeroes.Substring(2).TrimStart(c0);

            eserAccount = eserLeftPart + eserMidPart + eserRightPart;
        }

        // helper function: computes eser account (9 digits)
        internal void GetEserFor9DigitAccount(string blz, string account10Digits, out string eserAccount, out string eserLeftPart, out string eserMidPart, out string eserRightPart)
        {
            // validate rules
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);
            if (accountWithoutLeadingZeroes.Length != 9) throw new BankAccountValidation.BankException("argument:1103", String.Format("algorithm is not applicable because account without leading zeroes '{0}' does not contain exactly 9 digits", accountWithoutLeadingZeroes));

            eserLeftPart = blz.Substring(4, 2) + accountWithoutLeadingZeroes[1] + blz.Substring(7, 1);
            eserMidPart = accountWithoutLeadingZeroes[0].ToString() + accountWithoutLeadingZeroes[2].ToString();
            eserRightPart = accountWithoutLeadingZeroes.Substring(3).TrimStart(c0);

            eserAccount = eserLeftPart + eserMidPart + eserRightPart;
        }
    
        // converts a string into a byte array
        // (every character digit in the string represents one byte digit)
        internal byte[] GetByteArrayOfString(string value)
        {
            byte[] accountDigits = new byte[value.Length];

            for (int i = 0; i < value.Length; i++)
            {
                if (!Char.IsDigit(value[i])) throw new ChecksumException("argument:1103", String.Format("value '{0}' contains no-digit '{1}'", value, value[i]));
                accountDigits[i] = byte.Parse(value[i].ToString());
            }

            TraceTemporaryResult(accountDigits);
            return accountDigits;
        }

        // displays cyclic weighting factors from left to right
        private void TraceWeightingFromLeftToRight(byte[] weighting, int startPosition, int countFactors)
        {
            if (countFactors < 0) throw new ChecksumException("argument:1105", String.Format("count factors {0} is out of bounds", countFactors.ToString()));

            traceManager.Trace("weighting:      ", TraceManager.VerboseMode.VeryVeryVerbose, true);

            // indent
            for (int i = 0; i < startPosition; i++) traceManager.Trace("   ", TraceManager.VerboseMode.VeryVeryVerbose, false);

            int weightingIndex = 0;
            for (int accountDigitsIndex = startPosition; accountDigitsIndex < countFactors; accountDigitsIndex++)
            {
                traceManager.Trace(weighting[weightingIndex].ToString().PadLeft(3), TraceManager.VerboseMode.VeryVeryVerbose, false);
                weightingIndex = (byte)((weightingIndex + 1) % weighting.Length);
            }

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose, true);
        }

        // displays cyclic weighting factors from right to left
        internal void TraceWeightingFromRightToLeft(byte[] weighting, int countFactors)
        {
            if (countFactors < 0) throw new ChecksumException("argument:1106", String.Format("count factors {0} is out of bounds", countFactors.ToString()));

            traceManager.Trace("weighting:      ", TraceManager.VerboseMode.VeryVeryVerbose, true);

            StringBuilder weightingTable = new StringBuilder(80);

            int weightingIndex = 0;
            for (int accountDigitsIndex = countFactors - 1; accountDigitsIndex >= 0; accountDigitsIndex--)
            {
                weightingTable.Insert(0, weighting[weightingIndex].ToString().PadLeft(3));
                weightingIndex = (byte)((weightingIndex + 1) % weighting.Length);
            }

            traceManager.Trace(weightingTable.ToString(), TraceManager.VerboseMode.VeryVeryVerbose, false);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose, true);
        }
    
        // just traces the value of the given byte array
        internal void TraceTemporaryResult(byte[] values)
        {
            traceManager.Trace("byte array:     ", TraceManager.VerboseMode.VeryVeryVerbose, true);
            foreach (byte b in values) traceManager.Trace(b.ToString().PadLeft(3), TraceManager.VerboseMode.VeryVeryVerbose, false);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose, true);
        }

    }
}
