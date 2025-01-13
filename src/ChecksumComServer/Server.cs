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

using ChecksumValidation;
using ChecksumValidation.BankAccountValidation;
using ChecksumValidation.CreditCardValidation;
using ChecksumValidation.IbanValidation;
using ChecksumValidation.IdentityValidation;

namespace ChecksumValidation.ChecksumServer
{
    public sealed class Server
    {
        // private constants
        private const string cDefaultBankDirectory = ".";

        // private members
        TraceManager traceManager = null;
        BankAccountValidator bankAccountValidator = null;
        IbanValidator ibanValidator = null;
        CreditCardValidator creditCardValidator = null;
        IdentityValidator identityValidator = null;

        public Server()
        {
            // tracing
            traceManager = new TraceManager(TraceManager.VerboseMode.None, Console.Out);

            // validators
            bankAccountValidator = new BankAccountValidator(traceManager, cDefaultBankDirectory);
            ibanValidator = new IbanValidator(traceManager);
            creditCardValidator = new CreditCardValidator(traceManager);
            identityValidator = new IdentityValidator(traceManager);
        }

        // com interface (specific): set bank directory
        public void SetBankDirectory(string dir)
        {
            bankAccountValidator = new BankAccountValidator(traceManager, dir);
        }

        // com interface: bank account validation
        public void LoadBankDirectory()
        {
            bankAccountValidator.Load();
        }

        public void ValidateBankAccount(string blz, string account)
        {
            bankAccountValidator.Load(); // necessary if COM client doesn't explicitly invoke LoadBankDirectory() before; does nothing if already loaded
            bankAccountValidator.Validate(blz, account);
        }

        public string FormatBlz(string blz)
        {
            return bankAccountValidator.FormatBlz(blz);
        }

        // com interface: iban validation
        public void ValidateIban(string iban)
        {
            ibanValidator.Validate(iban);
        }

        // com interface: iban formatting
        public string FormatIban(string iban)
        {
            return ibanValidator.FormatIban(iban);
        }

        // com interface: iban conversion
        public string ToIban(string blz, string account)
        {
            return ibanValidator.ToIban(blz, account);
        }

        // com interface: credit card validation
        public void ValidateCreditCard(string creditCardNumber)
        {
            creditCardValidator.Validate(creditCardNumber);
        }

        // com interface: credit card identification
        public string GetCreditCardType(string creditCardNumber)
        {
            return creditCardValidator.GetCreditCardType(creditCardNumber);
        }

        // com interface: german identity card validation
        public void ValidateGermanIdentityCard(string identityId)
        {
            identityValidator.Validate(IdentityValidator.IdentityType.GermanIdentityCard, identityId);
        }

        public void ValidateGermanPassport(string identityId)
        {
            identityValidator.Validate(IdentityValidator.IdentityType.GermanPassport, identityId);
        }
    }
}
