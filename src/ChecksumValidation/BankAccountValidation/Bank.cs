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

namespace ChecksumValidation.BankAccountValidation
{
    public sealed class Bank
    {
        // private members
        private string blz;          // 10020000
        private string checksumCode; // 69

        // public properties    
        public string Blz
        {
            get { return blz; }
            set { blz = value; }
        }

        public string ChecksumCode
        {
            get { return checksumCode; }
            set { checksumCode = value; }
        }

        // public constructors
        internal Bank(string blz, string checksumCode)
        {
            if (String.IsNullOrEmpty(blz)) throw new ChecksumException("argument:1601", "blz must not be empty");
            if (String.IsNullOrEmpty(checksumCode)) throw new ChecksumException("argument:1602", "checksum code must not be empty");

            RegexChecker.ValidateBlz(blz);
            RegexChecker.ValidateChecksumCode(checksumCode);

            this.blz = blz;
            this.checksumCode = checksumCode;
        }
    }
}
