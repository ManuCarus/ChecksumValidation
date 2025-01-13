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

namespace ChecksumValidation.IdentityValidation
{
    public sealed class IdentityValidator
    {
        // supported types
        public enum IdentityType
        {
            GermanIdentityCard,
            GermanPassport
        }

        // weighting
        private static byte[] cWeighting_7_3_1 = { 7, 3, 1 };

        // private members
        private TraceManager traceManager;
        private ValidationUtilities validationUtilities;

        // ctor
        public IdentityValidator(TraceManager traceManager)
        {
            this.traceManager = traceManager;
            this.validationUtilities = new ValidationUtilities(traceManager);
        }

        // validate identity card against computed checksums
        public void Validate(string identityType, string identityId)
        {
            if (identityType == null || identityType.Length == 0) throw new NullReferenceException("identity type must not be empty");

            object objIdentityType = Enum.Parse(typeof(IdentityType), identityType, false);

            if (objIdentityType == null) throw new ArgumentException("invalid identity type ('" + identityId + "')", "strPersonalIdentityId");
            if (objIdentityType.GetType() != typeof(IdentityType)) throw new InvalidCastException("type mismatch (personal identity type '" + identityId + "' is not of type '" + objIdentityType.GetType().FullName + "')");

            IdentityType enmIdentityType = (IdentityType)objIdentityType;
            Validate(enmIdentityType, identityId);
        }
    
        public void Validate(IdentityType identityType, string identityId)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("identity id:      {0}", identityId), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("identity type:    {0}", Enum.GetName(identityType.GetType(), identityType)), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            // validation
            if (String.IsNullOrEmpty(identityId)) throw new ChecksumException("argument:1701", "identity id must not be empty");
            ValidateRegExIdentity(identityType, identityId);

            // splitting
            string bkz; // "2406"
            string serialNumber; // e.g. "05568"
            string checksumSerialNumber; // e.g. "4"
            string birthDate; // e.g. "681020"
            string checksumBirthDate; // e.g. "3"
            string expirationDate; // e.g. "070510"
            string checksumExpirationDate; // e.g. "9"
            string checksumTotals; // e.g. "6"

            switch (identityType)
            {
                case IdentityType.GermanIdentityCard:
                case IdentityType.GermanPassport: SplitIdentityId(    identityId,
                                                                  out bkz,
                                                                  out serialNumber,
                                                                  out checksumSerialNumber,
                                                                  out birthDate,
                                                                  out checksumBirthDate,
                                                                  out expirationDate,
                                                                  out checksumExpirationDate,
                                                                  out checksumTotals);

                    break;

                default: throw new ChecksumException("argument:1702", String.Format("identity type isn't known ('{0}')", Enum.GetName(typeof(IdentityType), identityType)));
            }

            // convert digits into array of bytes
            byte[] bkzSerialNumber = validationUtilities.GetByteArrayOfString(bkz + serialNumber);

            // serial checksum:
            // - multiply digits with weighting array
            // - add all digits
            // - compute checksum
            // - compare checksums

            validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(bkzSerialNumber, cWeighting_7_3_1);
            validationUtilities.ApplyModuloToEachDigit(bkzSerialNumber, 10);
            int sum = validationUtilities.AddAllValues(bkzSerialNumber);
            byte computedChecksumSerialNumber = (byte)(sum % 10);
            string strComputedChecksumSerialNumber = computedChecksumSerialNumber.ToString();

            traceManager.Trace(String.Format("serial checksum:  {0}", strComputedChecksumSerialNumber), TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumSerialNumber.CompareTo(checksumSerialNumber) == 0) traceManager.TraceLine(" --> OK", TraceManager.VerboseMode.VeryVerbose, true);
            else traceManager.TraceLine(" --> ERROR", TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumSerialNumber.CompareTo(checksumSerialNumber) != 0) throw new IdentityValidationException("validation:3101", String.Format("parity failure -> computed serial number checksum = '{0}' <> '{1}' = given checksum", strComputedChecksumSerialNumber, checksumSerialNumber), Enum.GetName(identityType.GetType(), identityType), identityId);

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            // birthdate checksum

            byte[] birthday = validationUtilities.GetByteArrayOfString(birthDate);
            validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(birthday, cWeighting_7_3_1);
            validationUtilities.ApplyModuloToEachDigit(birthday, 10);
            sum = validationUtilities.AddAllValues(birthday);
            byte computedChecksumBirthday = (byte)(sum % 10);
            string strComputedChecksumBirthday = computedChecksumBirthday.ToString();

            traceManager.Trace(String.Format("birth checksum:   {0}", strComputedChecksumBirthday), TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumBirthday.CompareTo(checksumBirthDate) == 0) traceManager.TraceLine(" --> OK", TraceManager.VerboseMode.VeryVerbose, true);
            else traceManager.TraceLine(" --> ERROR", TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumBirthday.CompareTo(checksumBirthDate) != 0) throw new IdentityValidationException("validation:3102", String.Format("parity failure -> computed birthdate checksum = '{0}' <> '{1}' = given checksum", strComputedChecksumBirthday, checksumBirthDate), Enum.GetName(identityType.GetType(), identityType), identityId);

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            // expiration date checksum

            byte[] expirationDay = validationUtilities.GetByteArrayOfString(expirationDate);
            validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(expirationDay, cWeighting_7_3_1);
            validationUtilities.ApplyModuloToEachDigit(expirationDay, 10);
            sum = validationUtilities.AddAllValues(expirationDay);
            byte computedChecksumExpirationDate = (byte)(sum % 10);
            string strComputedChecksumExpirationDay = computedChecksumExpirationDate.ToString();

            traceManager.Trace(String.Format("expiry checksum:  {0}", strComputedChecksumExpirationDay), TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumExpirationDay.CompareTo(checksumExpirationDate) == 0) traceManager.TraceLine(" --> OK", TraceManager.VerboseMode.VeryVerbose, true);
            else traceManager.TraceLine(" --> ERROR", TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumExpirationDay.CompareTo(checksumExpirationDate) != 0) throw new IdentityValidationException("validation:3103", String.Format("parity failure -> computed expiration date checksum = '{0}' <> '{1}' = given checksum", strComputedChecksumExpirationDay, checksumExpirationDate), Enum.GetName(identityType.GetType(), identityType), identityId);

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            // total checksum

            string relevantDigits = bkz + serialNumber + strComputedChecksumSerialNumber + birthDate + strComputedChecksumBirthday + expirationDate + strComputedChecksumExpirationDay;

            byte[] totals = validationUtilities.GetByteArrayOfString(relevantDigits);
            validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(totals, cWeighting_7_3_1);
            validationUtilities.ApplyModuloToEachDigit(totals, 10);
            sum = validationUtilities.AddAllValues(totals);
            byte computedChecksumTotals = (byte)(sum % 10);
            string strComputedChecksumTotals = computedChecksumTotals.ToString();

            traceManager.Trace(String.Format("total checksum:   {0}", strComputedChecksumTotals), TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumTotals.CompareTo(checksumTotals) == 0) traceManager.TraceLine(" --> OK", TraceManager.VerboseMode.VeryVerbose, true);
            else traceManager.TraceLine(" --> ERROR", TraceManager.VerboseMode.VeryVerbose, true);

            if (strComputedChecksumTotals.CompareTo(checksumTotals) != 0) throw new IdentityValidationException("validation:3104", String.Format("parity failure -> computed totals checksum = '{0}' <> '{1}' = given checksum", strComputedChecksumTotals, checksumTotals), Enum.GetName(identityType.GetType(), identityType), identityId);
        }

        // validates identity against regular expression. 
        // throws ArgumentException if match fails.
        private void ValidateRegExIdentity(IdentityType identityType, string identityId)
        {
            switch (identityType)
            {
                case IdentityType.GermanIdentityCard: RegexChecker.ValidateGermanIdentityCard(identityId); break;
                case IdentityType.GermanPassport: RegexChecker.ValidateGermanPassport(identityId); break;

                default: throw new ChecksumException("argument:1703", String.Format("personal identity type isn't known ('{0}')", Enum.GetName(typeof(IdentityType), identityType)));
            }
        }

        // splits personal identity id into its serial number, birthdate, expiration date and checksums
        private void SplitIdentityId(    string identityId,
                                     out string bkz,
                                     out string serialNumber,
                                     out string checksumSerialNumber,
                                     out string birthDate,
                                     out string checksumBirthDate,
                                     out string expirationDate,
                                     out string checksumExpirationDate,
                                     out string checksumTotals)
        {
            bkz = identityId.Substring(0, 4);
            serialNumber = identityId.Substring(4, 5);
            checksumSerialNumber = identityId.Substring(9, 1);
            birthDate = identityId.Substring(13, 6);
            checksumBirthDate = identityId.Substring(19, 1);
            expirationDate = identityId.Substring(21, 6);
            checksumExpirationDate = identityId.Substring(27, 1);
            checksumTotals = identityId.Substring(identityId.Length - 1, 1);

            traceManager.TraceLine(String.Format("BKZ:             {0}", bkz), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("serial number:   {0}", serialNumber), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("checksum PSN:    {0}", checksumSerialNumber), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("birthdate:       {0}", birthDate), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("checksum PGD:    {0}", checksumBirthDate), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("expiration date: {0}", expirationDate), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("checksum PAD:    {0}", checksumExpirationDate), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(String.Format("checksum P:      {0}", checksumTotals), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
        }

    }
}
