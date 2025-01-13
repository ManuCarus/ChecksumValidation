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

namespace ChecksumValidation
{
    public class CommandHandler
    {
        // allowed commands
        public const string cCmdCache = "cache";
        public const string cCmdAccount = "account:";
        public const string cCmdFormatBlz = "format-blz:";
        public const string cCmdIban = "iban:";
        public const string cCmdToIban = "to-iban:";
        public const string cCmdFormatIban = "format-iban:";
        public const string cCmdIdentity = "identity:";
        public const string cCmdPassport = "passport:";
        public const string cCmdCreditCard = "credit-card:";
        public const string cCmdGetCreditCardType = "get-credit-card-type:";
        public const string cCmdStop = "stop";

        public static void SplitAccountData(string command, out string blz, out string account)
        {
            // syntax:  "account:<account>/<blz>"
            // example: "account:1234567897/37050299"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1001", "no value for account/blz");
            if (parts.Length > 2) throw new ChecksumException("argument:1002", "too many values for account/blz");

            string[] blzAccount = parts[1].Split(new char[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (blzAccount.Length != 2) throw new ChecksumException("argument:1003", "invalid value for account/blz");

            account = blzAccount[0];
            blz = blzAccount[1];

            return;
        }

        public static string SplitFormatBlzData(string command)
        {
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1004", "no value for blz");
            if (parts.Length > 2) throw new ChecksumException("argument:1005", "too many values for blz");
            string blz = parts[1];

            return blz;
        }

        public static string SplitIbanData(string command)
        {
            // syntax:  "iban:<iban>"
            // example: "iban:DE60700517550000007229"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1006", "no value for iban");
            if (parts.Length > 2) throw new ChecksumException("argument:1007", "too many values for iban");
            string iban = parts[1];

            return iban;
        }

        public static void SplitToIbanData(string command, out string blz, out string account)
        {
            // syntax:  "to-iban:<account>/<blz>"
            // example: "to-iban:1234567890/37050299"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1008", "no value for account/blz");
            if (parts.Length > 2) throw new ChecksumException("argument:1009", "too many values for account/blz");

            string[] blzAccount = parts[1].Split(new char[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (blzAccount.Length != 2) throw new ChecksumException("argument:1010", "invalid value for account/blz");

            account = blzAccount[0];
            blz = blzAccount[1];

            return;
        }

        public static string SplitFormatIbanData(string command)
        {
            // syntax:  "format-iban:<iban>"
            // example: "format-iban:DE60700517550000007229"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1011", "no value for iban");
            if (parts.Length > 2) throw new ChecksumException("argument:1012", "too many values for iban");
            string iban = parts[1];

            return iban;
        }

        public static string SplitIdentityData(string command)
        {
            // syntax:  "identity:<identity>"
            // example: "identity:2406055684D<<6810203<0705109<<<<<<6"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1013", "no value for identity id");
            if (parts.Length > 2) throw new ChecksumException("argument:1014", "too many values for identity id");
            string identityId = parts[1];

            return identityId;
        }

        public static string SplitPassportData(string command)
        {
            // syntax:  "passport:<passport>"
            // example: "passport:2406055684D<<6810203M0705109<<<<<<<<<<<<<<<6"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1015", "no value for passport id");
            if (parts.Length > 2) throw new ChecksumException("argument:1016", "too many values for passport id");
            string identityId = parts[1];

            return identityId;
        }

        public static string SplitCreditCardData(string command)
        {
            // syntax:  "credit-card:<creditcard>"
            // example: "credit-card:4509472140549006"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1017", "no value for credit card");
            if (parts.Length > 2) throw new ChecksumException("argument:1018", "too many values for credit card");
            string creditCardNumber = parts[1];

            return creditCardNumber;
        }

        public static string SplitToCreditCardInstituteData(string command)
        {
            // syntax:  "to-credit-card-institute:<creditcard>"
            // example: "to-credit-card-institute:4509472140549006"
            string[] parts = command.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) throw new ChecksumException("argument:1019", "no value for credit card");
            if (parts.Length > 2) throw new ChecksumException("argument:1020", "too many values for credit card");
            string creditCardNumber = parts[1];

            return creditCardNumber;
        }
    }
}
