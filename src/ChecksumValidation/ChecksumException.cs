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

/*
   Error Codes are structured like this: "<category>:<number>" (e.g. "argument:4711").
   Assigned numbers are:
  
   --------------+------------+------------------------
   Category      |    Range   | Assigned Source Code
   --------------+------------+------------------------
   argument      | 1001..1024 | Listener.cs  
                 | 1101..1106 | ValidationUtilities.cs 
                 | 1201..1211 | IbanValidator.cs 
                 | 1301..1308 | CreditCardValidator.cs 
                 | 1401..1403 | BankAccountValidator.cs 
                 | 1501..1501 | RegexChecker.cs 
                 | 1601..1605 | Bank.cs 
                 | 1701..1703 | IdentityValidator.cs 
   --------------+------------+------------------------
   authorization | 2001..2001 | Listener.cs  
   --------------+------------+------------------------
   validation    | 3001..3002 | ValidationUtilities.cs  
                 | 3101..3104 | IdentityValidator.cs  
                 | 3201..3202 | IbanValidator.cs  
                 | 3301..3302 | CreditCardValidator.cs  
                 | 3401..3458 | BankAccountValidator.cs  
   --------------+------------+------------------------
   configuration | 4001..4001 | BankAccountValidator.cs  
   --------------+------------+------------------------
   internal      | 9999..9999 | Listener.cs  
   --------------+------------+------------------------
*/

namespace ChecksumValidation
{
    public class ChecksumException : ApplicationException
    {
        // private members
        private string code;

        // ctors
        public ChecksumException(string code, string message) : base(message)
        {
            if (String.IsNullOrEmpty(code)) throw new NullReferenceException("code must not be empty");
            if (String.IsNullOrEmpty(message)) throw new NullReferenceException("message must not be empty");

            this.code = code;
        }

        public ChecksumException(string code, string message, Exception ex) : base(message, ex)
        {
            if (String.IsNullOrEmpty(code)) throw new NullReferenceException("code must not be empty");
            if (String.IsNullOrEmpty(message)) throw new NullReferenceException("message must not be empty");
            if (ex == null) throw new NullReferenceException("exception must not be empty");

            this.code = code;
        }

        // internal properties
        public string Code
        {
            get { return this.code; }
        }
    }
}
