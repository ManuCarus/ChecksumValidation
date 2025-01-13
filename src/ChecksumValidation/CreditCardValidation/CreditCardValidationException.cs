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

namespace ChecksumValidation.CreditCardValidation
{
    public sealed class CreditCardValidationException : ChecksumException
    {
        // private members
        private string creditCardNumber;

        // ctors
        public CreditCardValidationException(string code, string message, string creditCardNumber) : base(code, message)
        {
            if (String.IsNullOrEmpty(code)) throw new NullReferenceException("code must not be empty");
            if (String.IsNullOrEmpty(message)) throw new NullReferenceException("message must not be empty");
            if (String.IsNullOrEmpty(creditCardNumber)) throw new NullReferenceException("credit card number must not be empty");

            this.creditCardNumber = creditCardNumber;
        }

        public CreditCardValidationException(string code, string message, string creditCardNumber, Exception ex) : base(code, message, ex)
        {
            if (String.IsNullOrEmpty(code)) throw new NullReferenceException("code must not be empty");
            if (String.IsNullOrEmpty(message)) throw new NullReferenceException("message must not be empty");
            if (String.IsNullOrEmpty(creditCardNumber)) throw new NullReferenceException("credit card number must not be empty");
            if (ex == null) throw new NullReferenceException("exception must not be empty");

            this.creditCardNumber = creditCardNumber;
        }
    }
}
