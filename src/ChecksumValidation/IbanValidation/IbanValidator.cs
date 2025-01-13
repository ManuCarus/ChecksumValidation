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
using System.Text;

namespace ChecksumValidation.IbanValidation
{
    public sealed class IbanValidator
    {
        // helper class to hold maximum amount of digits for country-specific BLZs and account numbers
        internal sealed class IbanLength
        {
            private byte lengthBlz;
            private byte lengthAccount;

            // properties
            internal byte LengthBlz
            {
                get { return lengthBlz; }
            }

            internal byte LengthAccount
            {
                get { return lengthAccount; }
            }

            // ctor
            internal IbanLength(byte lengthBlz, byte lengthAccount)
            {
                this.lengthBlz = lengthBlz;
                this.lengthAccount = lengthAccount;
            }
        }

        // utility class that maintains valid iban lengths of different countries
        internal sealed class IbanLengthValidator
        {
            // hashtable to store country code and blz/account lengths
            private Hashtable ibanLengths;

            // ctor
            internal IbanLengthValidator()
            {
                ibanLengths = new Hashtable(20);

                ibanLengths.Add((string)"BE", new IbanLength(3, 9));
                ibanLengths.Add((string)"DK", new IbanLength(4, 10));
                ibanLengths.Add((string)"DE", new IbanLength(8, 10));
                ibanLengths.Add((string)"FI", new IbanLength(6, 8));
                ibanLengths.Add((string)"FR", new IbanLength(10, 13));
                ibanLengths.Add((string)"GB", new IbanLength(4, 14));
                ibanLengths.Add((string)"IE", new IbanLength(4, 14));
                ibanLengths.Add((string)"IS", new IbanLength(4, 18));
                ibanLengths.Add((string)"IT", new IbanLength(11, 12));
                ibanLengths.Add((string)"LU", new IbanLength(3, 13));
                ibanLengths.Add((string)"NL", new IbanLength(4, 10));
                ibanLengths.Add((string)"NO", new IbanLength(4, 7));
                ibanLengths.Add((string)"AT", new IbanLength(5, 11));
                ibanLengths.Add((string)"PL", new IbanLength(8, 16));
                ibanLengths.Add((string)"PT", new IbanLength(8, 13));
                ibanLengths.Add((string)"SE", new IbanLength(3, 17));
                ibanLengths.Add((string)"CH", new IbanLength(5, 12));
                ibanLengths.Add((string)"ES", new IbanLength(8, 12));
            }

            // country-specific retrieval of IbanLength
            internal IbanLength GetIbanLength(string isoCode2)
            {
                Object ibanLength = ibanLengths[isoCode2];

                if (ibanLength == null) throw new ArgumentException(String.Format("unknown iso code 2 '{0}'", isoCode2));

                return (IbanLength)ibanLength;
            }
        }

        // constant declarations
        private static byte cIbanMaxCharacters = 34;
        private static byte cIbanCountDigitGroup = 9;
        private static byte cIbanDivisor = 97;
        private static byte cIbanSubtraction = 98;
        private static byte cIbanCountFormatDigitGroup = 4;
        private static byte cMaxDigitsAccount = 10;

        private static string cDE = "DE";
        private static string c00 = "00";

        // private members
        private IbanLengthValidator ibanLengthValidator;
        private TraceManager traceManager;
        private ValidationUtilities validationUtilities;

        // ctor
        public IbanValidator(TraceManager traceManager)
        {
            this.ibanLengthValidator = new IbanLengthValidator();
            this.traceManager = traceManager;
            this.validationUtilities = new ValidationUtilities(traceManager);
        }

        // validate IBAN against computed checksum
        public void Validate(string iban)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("iban:                 {0}", iban.ToString()), TraceManager.VerboseMode.VeryVerbose);

            // validation
            if (String.IsNullOrEmpty(iban)) throw new NullReferenceException("iban must not be empty");
            RegexChecker.ValidateIban(iban);

            // splitting
            string isoCode2;
            string givenChecksum;
            string blz;
            string account;

            SplitIban(iban, out isoCode2, out givenChecksum, out blz, out account);

            if (isoCode2 == null) throw new IbanValidationException("argument:1201", "iso code 2 must not be empty", iban);
            if (isoCode2.Length != 2) throw new IbanValidationException("argument:1202", String.Format("invalid iso code 2 '{0}'", isoCode2), iban);
            if (givenChecksum == null) throw new IbanValidationException("argument:1203", "checksum must not be empty", iban);
            if (givenChecksum.Length != 2) throw new IbanValidationException("argument:1204", String.Format("invalid checksum '{0}'", givenChecksum), iban);
            if (String.IsNullOrEmpty(blz)) throw new IbanValidationException("argument:1205", "blz must not be empty", iban);
            if (String.IsNullOrEmpty(account)) throw new IbanValidationException("argument:1206", "account must not be empty", iban);

            // algorithm
            string modifiedIban = MoveCountryCodeToEndAndSetChecksumTo00(iban);
            modifiedIban = TransformIbanCharacters(modifiedIban);
            byte remainder = GetRemainder(modifiedIban, cIbanDivisor);

            // compute checksum
            byte computedChecksum = (byte)(cIbanSubtraction - remainder);

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("temporary checksum:   {0}", computedChecksum.ToString()), TraceManager.VerboseMode.VeryVerbose);

            string strComputedChecksum;

            if (computedChecksum < 10) strComputedChecksum = "0" + computedChecksum.ToString();
            else strComputedChecksum = computedChecksum.ToString();

            if (strComputedChecksum.Length != 2) throw new IbanValidationException("validation:3201", String.Format("invalid computed checksum '{0}'", strComputedChecksum), iban);

            traceManager.Trace(String.Format("final checksum:       {0}", strComputedChecksum), TraceManager.VerboseMode.VeryVerbose, true);

            // compare checksums
            if (strComputedChecksum.CompareTo(givenChecksum) == 0) traceManager.TraceLine(" --> OK", TraceManager.VerboseMode.VeryVerbose, true);
            else traceManager.TraceLine(" --> ERROR", TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksum.CompareTo(givenChecksum) != 0) throw new IbanValidationException("validation:3202", String.Format("parity failure -> computed checksum = '{0}' <> '{1}' = given checksum", strComputedChecksum, givenChecksum), iban);
        }

        // splits IBAN into country code, checksum, blz and account number
        private void SplitIban(string iban, out string isoCode2, out string checksum, out string blz, out string account)
        {
            isoCode2 = iban.Substring(0, 2);
            checksum = iban.Substring(2, 2);

            IbanLength ibanLength = ibanLengthValidator.GetIbanLength(isoCode2);

            if (ibanLength == null)
            {
                // country code could not be found in hash table, so there's no algorithm implemented
                throw new ArgumentException(String.Format("unknown iso code 2 -> there's no algorithm implemented for iso code 2 '{0}'", isoCode2));
            }

            int countAllowedCharacters = 2 + 2 + ibanLength.LengthBlz + ibanLength.LengthAccount;

            if (iban.Length != countAllowedCharacters)
            {
                // IBAN is invalid since either blz and account number are not fully contained or more characters are provided than allowed
                throw new ArgumentException(String.Format("invalid IBAN -> '{0}' contains {1} characters but must have exactly 2 + 2 + {2} + {3} = {4} characters)", iban, iban.Length.ToString(), ibanLength.LengthBlz.ToString(), ibanLength.LengthAccount.ToString(), countAllowedCharacters.ToString()));
            }

            blz = iban.Substring(4, ibanLength.LengthBlz);
            account = iban.Substring(4 + ibanLength.LengthBlz, ibanLength.LengthAccount);

            traceManager.TraceLine(String.Format("iso code 2:     {0}", isoCode2), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("given checksum: {0}", checksum), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("blz:            {0}", blz), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("account number: {0}", account), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
        }

        // cuts country code and checksum from the beginning, pastes the country code to the end of the iban and sets the checksum to "00"
        private string MoveCountryCodeToEndAndSetChecksumTo00(string iban)
        {
            string modifiedIban = iban.Substring(4) + iban.Substring(0, 2) + "00";
            traceManager.TraceLine(String.Format("modified IBAN:  {0}", modifiedIban), TraceManager.VerboseMode.VeryVerbose);
            return modifiedIban;
        }

        // computes a german IBAN when given a valid (german) BLZ and account number
        public string ToIban(string blz, string account)
        {
            if (String.IsNullOrEmpty(blz)) throw new ChecksumException("argument:1206", "blz must not be empty");
            if (String.IsNullOrEmpty(account)) throw new ChecksumException("argument:1207", "account must not be empty");

            // validation
            RegexChecker.ValidateBlz(blz);
            RegexChecker.ValidateAccount(account);

            // algorithm
            string iban = cDE + c00 + blz + account.PadLeft(cMaxDigitsAccount, '0');

            traceManager.TraceLine(String.Format("prepared IBAN:        {0}", iban), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            string modifiedIban = MoveCountryCodeToEndAndSetChecksumTo00(iban);
            modifiedIban = TransformIbanCharacters(modifiedIban);
            byte remainder = GetRemainder(modifiedIban, cIbanDivisor);

            // compute checksum
            byte computedChecksum = (byte)(cIbanSubtraction - remainder);

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("temporary checksum:   {0}", computedChecksum.ToString()), TraceManager.VerboseMode.VeryVerbose);

            string strComputedChecksum;

            if (computedChecksum < 10) strComputedChecksum = "0" + computedChecksum.ToString();
            else strComputedChecksum = computedChecksum.ToString();

            traceManager.TraceLine(String.Format("final checksum:       {0}", strComputedChecksum), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            string finalIban = cDE + strComputedChecksum + blz + account.PadLeft(cMaxDigitsAccount, '0');

            traceManager.TraceLine(String.Format("final IBAN:           {0}", finalIban), TraceManager.VerboseMode.VeryVerbose);

            return finalIban;
        }

        // formats IBAN into 4-digit groups
        public string FormatIban(string iban)
        {
            // validation
            if (String.IsNullOrEmpty(iban)) throw new ChecksumException("argument:1208", "IBAN must not be empty");
            RegexChecker.ValidateIban(iban);

            StringBuilder formattedIban = new StringBuilder(iban.Length + (int)(cIbanMaxCharacters / cIbanCountFormatDigitGroup) + 1);

            int position = 0;
            while (position < iban.Length)
            {
                if (position + cIbanCountFormatDigitGroup < iban.Length) formattedIban.Append(iban.Substring(position, cIbanCountFormatDigitGroup) + " ");
                else formattedIban.Append(iban.Substring(position));

                position += cIbanCountFormatDigitGroup;
            }

            if (formattedIban[formattedIban.Length - 1] == ' ') formattedIban.Remove(formattedIban.Length - 1, 1);

            this.traceManager.TraceLine(formattedIban.ToString(), TraceManager.VerboseMode.VeryVerbose);
            return formattedIban.ToString();
        }

        // helper function: transforms every character A..Z into a 2-digit number (A -> 10, ..., Z -> 35)
        private string TransformIbanCharacters(string iban)
        {
            StringBuilder ibanDigits = new StringBuilder(iban.Length * 2);
            char currentIbanCharacter;

            for (int i = 0; i < iban.Length; i++)
            {
                currentIbanCharacter = iban[i];

                if (Char.IsDigit(currentIbanCharacter))
                {
                    ibanDigits.Append(currentIbanCharacter);
                }
                else if (Char.IsLetter(currentIbanCharacter))
                {
                    byte value;

                    switch (currentIbanCharacter)
                    {
                        case 'A': value = 10; break;
                        case 'B': value = 11; break;
                        case 'C': value = 12; break;
                        case 'D': value = 13; break;
                        case 'E': value = 14; break;
                        case 'F': value = 15; break;
                        case 'G': value = 16; break;
                        case 'H': value = 17; break;
                        case 'I': value = 18; break;
                        case 'J': value = 19; break;
                        case 'K': value = 20; break;
                        case 'L': value = 21; break;
                        case 'M': value = 22; break;
                        case 'N': value = 23; break;
                        case 'O': value = 24; break;
                        case 'P': value = 25; break;
                        case 'Q': value = 26; break;
                        case 'R': value = 27; break;
                        case 'S': value = 28; break;
                        case 'T': value = 29; break;
                        case 'U': value = 30; break;
                        case 'V': value = 31; break;
                        case 'W': value = 32; break;
                        case 'X': value = 33; break;
                        case 'Y': value = 34; break;
                        case 'Z': value = 35; break;

                        default: throw new ChecksumException("argument:1209", String.Format("invalid IBAN -> '{0}' contains invalid character '{1}'", iban, currentIbanCharacter));
                    }

                    ibanDigits.Append(value.ToString());
                }
                else
                {
                    throw new ChecksumException("argument:1210", String.Format("invalid IBAN -> '{0}' contains invalid character '{1}'", iban, currentIbanCharacter));
                }
            }

            string modifiedIban = ibanDigits.ToString();

            traceManager.TraceLine(String.Format("modified IBAN:  {0}", modifiedIban), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            return modifiedIban;
        }

        // helper function: divides a big number and returns its remainder
        private byte GetRemainder(string bigNumber, byte divisor)
        {
            string modifiedBigNumber = bigNumber;
            string modifiedBigNumberRest;
            string strDigitGroup;
            Int32 digitGroup;
            int remainder = 0;
            bool mustContinue = true;
            int countWatchDog = 0;
            int countMaxLoops = (int)(cIbanMaxCharacters / cIbanCountDigitGroup) + 1;

            while (mustContinue)
            {
                if (modifiedBigNumber.Length > cIbanCountDigitGroup)
                {
                    strDigitGroup = modifiedBigNumber.Substring(0, cIbanCountDigitGroup);
                    modifiedBigNumberRest = modifiedBigNumber.Substring(cIbanCountDigitGroup);
                }
                else
                {
                    strDigitGroup = modifiedBigNumber.Substring(0);
                    modifiedBigNumberRest = null;
                    mustContinue = false;
                }

                digitGroup = Int32.Parse(strDigitGroup);
                remainder = digitGroup % divisor;

                traceManager.TraceLine(String.Format("digit group:    {0} mod {1} = {2}", strDigitGroup, divisor.ToString(), remainder.ToString()), TraceManager.VerboseMode.VeryVerbose);

                modifiedBigNumber = remainder.ToString() + modifiedBigNumberRest;

                countWatchDog++;
                if (countWatchDog > countMaxLoops) throw new ChecksumException("argument:1211", String.Format("internal error -> GetRemainder() ran into infinite loop ({0} passes)", countWatchDog.ToString()));
            }

            return (byte)remainder;
        }

    }
}
