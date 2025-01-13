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
using System.Configuration;

using ChecksumValidation.BankAccountValidation;
using ChecksumValidation.CreditCardValidation;
using ChecksumValidation.IbanValidation;
using ChecksumValidation.IdentityValidation;

namespace ChecksumValidation.ChecksumClient.Proxy
{
    internal class InProcProxy : IProxy
    {
        // private constants
        private const string cDefaultBankDirectory = ".";

        // private members
        private ParameterSet parameterSet;
        private TraceManager traceManager;
        private BankAccountValidator bankAccountValidator;
        private CreditCardValidator creditCardValidator;
        private IbanValidator ibanValidator;
        private IdentityValidator identityValidator;

        // ctor
        internal InProcProxy(ParameterSet parameterSet, TraceManager traceManager)
        {
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager not set!");

            this.parameterSet = parameterSet;
            this.traceManager = traceManager;

            string bankDirectory = parameterSet.BankDirectory;
            if (String.IsNullOrEmpty(bankDirectory)) bankDirectory = cDefaultBankDirectory;

            bankAccountValidator = new BankAccountValidator(traceManager, bankDirectory);
            ibanValidator = new IbanValidator(traceManager);
            creditCardValidator = new CreditCardValidator(traceManager);
            identityValidator = new IdentityValidator(traceManager);
        }

        // bank account validation
        public string LoadBankDirectory()
        {
            bankAccountValidator.Load();
            return CommandHandler.cResultOk;
        }

        public string ValidateBankAccount(string blz, string account)
        {
            bankAccountValidator.Load();
            bankAccountValidator.Validate(blz, account);
            return CommandHandler.cResultOk;
        }

        public string FormatBlz(string blz)
        {
            return bankAccountValidator.FormatBlz(blz);
        }

        // iban validation
        public string ValidateIban(string iban)
        {
            ibanValidator.Validate(iban);
            return CommandHandler.cResultOk;
        }

        public string FormatIban(string iban)
        {
            return ibanValidator.FormatIban(iban);
        }

        public string ToIban(string blz, string account)
        {
            return ibanValidator.ToIban(blz, account);
        }

        // credit card validation
        public string ValidateCreditCard(string creditCardNumber)
        {
            creditCardValidator.Validate(creditCardNumber);
            return CommandHandler.cResultOk;
        }

        public string GetCreditCardType(string creditCardNumber)
        {
            return creditCardValidator.GetCreditCardType(creditCardNumber);
        }

        // identity validation
        public string ValidateGermanIdentityCard(string identityId)
        {
            identityValidator.Validate(IdentityValidator.IdentityType.GermanIdentityCard, identityId);
            return CommandHandler.cResultOk;
        }

        public string ValidateGermanPassport(string identityId)
        {
            identityValidator.Validate(IdentityValidator.IdentityType.GermanPassport, identityId);
            return CommandHandler.cResultOk;
        }

    }
}
