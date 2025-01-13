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
using System.Text.RegularExpressions;

namespace ChecksumValidation
{
    internal sealed class RegexChecker
    {
        // regular expressions
        private static string cRegExIban = "^[A-Z]{2}[0-9]{2}[0-9A-Z]{1,30}$";
        private static string cRegExAccount = "^[0-9]{1,10}$";
        private static string cRegExBlz = "^[0-9]{8}$";
        private static string cRegexChecksumCode = "^[0-9A-Z]{2}$";
        private static string cRegExCreditCardNumber = "^[0-9]{13,16}$";
        private static string cRegExGermanIdentityCardId = "^[0-9]{4}[0-9]{5}[0-9][Dd]<<[0-9]{6}[0-9]<[0-9]{6}[0-9]<{6,7}[0-9]$";
        private static string cRegExGermanPassportId = "^[0-9]{4}[0-9]{5}[0-9][Dd]<<[0-9]{6}[0-9][MFmf][0-9]{6}[0-9]<{15}[0-9]$";

        // common validation routine
        internal static void Validate(string valueToCheck, string regex)
        {
            Regex objRegEx = new Regex(regex, RegexOptions.Compiled);
            if (!objRegEx.IsMatch(valueToCheck)) throw new ArgumentException("argument:1501", String.Format("expression '{0}' -> doesn't match regular expression '{1}'", valueToCheck, regex));
        }

        // specialized validation routines
        internal static void ValidateBlz(string blz)
        {
            Validate(blz,cRegExBlz);
        }

        internal static void ValidateAccount(string account)
        {
            Validate(account, cRegExAccount);
        }

        internal static void ValidateIban(string iban)
        {
            Validate(iban, cRegExIban);
        }

        internal static void ValidateChecksumCode(string checksumCode)
        {
            Validate(checksumCode, cRegexChecksumCode);
        }

        internal static void ValidateCreditCard(string creditCardNumber)
        {
            Validate(creditCardNumber, cRegExCreditCardNumber);
        }

        internal static void ValidateGermanIdentityCard(string identityId)
        {
            Validate(identityId, cRegExGermanIdentityCardId);
        }

        internal static void ValidateGermanPassport(string identityId)
        {
            Validate(identityId, cRegExGermanPassportId);
        }

    }
}
