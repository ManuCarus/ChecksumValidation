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

namespace ChecksumValidation.ChecksumClient
{
    internal interface IProxy
    {
        // bank account validation
        string LoadBankDirectory();
        string ValidateBankAccount(string blz, string account);
        string FormatBlz(string blz);

        // iban validation
        string ValidateIban(string iban);
        string FormatIban(string iban);
        string ToIban(string blz, string account);

        // credit card validation
        string ValidateCreditCard(string creditCardNumber);
        string GetCreditCardType(string creditCardNumber);

        // identity validation
        string ValidateGermanIdentityCard(string identityId);
        string ValidateGermanPassport(string identityId);
    }
}
