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
using NUnit.Framework;
using ChecksumValidation.BankAccountValidation;
using ChecksumValidation.CreditCardValidation;
using ChecksumValidation.IbanValidation;
using ChecksumValidation.IdentityValidation;

namespace ChecksumValidation.ChecksumUnitTest
{
    public partial class ValidationTester
    {
        private void NullReferenceExceptionTestForBankAccountValidation(string blz, string account)
        {
            try
            {
                bankAccountValidator.Validate(blz, account);

                throw new Exception("NullReferenceExceptionTestForBankAccountValidation(" + blz + "/" + account + ") should have thrown a NullReferenceException");
            }
            catch (NullReferenceException)
            {
                // ok, this is what we expected...
            }
        }


        private void ArgumentExceptionTestForBankAccountValidation(string blz, string account)
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);

            try
            {
                bankAccountValidator.Validate(blz, account);

                throw new Exception("ArgumentExceptionTestForBankAccountValidation(" + blz + "/" + account + ") should have thrown a ArgumentException");
            }
            catch (ArgumentException)
            {
                // ok, this is what we expected...
            }
        }

        private void VerifyNoBlzForAlgorithmExists(string checksumCode)
        {
            Hashtable banks = bankAccountValidator.Banks;
            Assert.IsNotNull(banks, "banks is null");

            string found = null;

            foreach (Object entry in banks.Values)
            {
                if (entry.GetType() != typeof(Bank)) throw new Exception("(" + checksumCode + "): type mismatch");

                Bank bank = (Bank)entry;

                if (bank.ChecksumCode.Equals(checksumCode))
                {
                    found = bank.Blz;
                    break;
                }
            }

            if (found != null) throw new Exception("(" + checksumCode + "): blz '" + found + "' is assigned to algorithm '" + checksumCode + "'");
        }

        private void InvalidBlzAccountCombinationTest(string blz, string account)
        {
            Assert.IsNotNull(blz);
            Assert.IsNotNull(account);

            Assert.IsTrue(blz.Length > 0);
            Assert.IsTrue(account.Length > 0);

            try
            {
                bankAccountValidator.Validate(blz, account);

                throw new Exception("(" + blz + "/" + account + ") should be invalid");
            }
            catch (BankException)
            {
                // ok: blz and account are invalid
            }
        }

        private void NullReferenceExceptionTestForCreditCardValidation(string creditCardNumber)
        {
            try
            {
                creditCardValidator.Validate(creditCardNumber);

                throw new Exception("NullReferenceExceptionTestForCreditCardValidation(" + creditCardNumber + ") should have thrown a NullReferenceException");
            }
            catch (NullReferenceException)
            {
                // ok, this is what we expected...
            }
        }

        private void ArgumentExceptionTestForCreditCardValidation(string creditCardNumber)
        {
            try
            {
                creditCardValidator.Validate(creditCardNumber);

                throw new Exception("ArgumentExceptionTestForBankAccountValidation(" + creditCardNumber + ") should have thrown a ArgumentException");
            }
            catch (ArgumentException)
            {
                // ok, this is what we expected...
            }
        }


        private void InvalidCreditCardTest(string creditCardNumber)
        {
            Assert.IsNotNull(creditCardNumber);
            Assert.IsTrue(creditCardNumber.Length > 0);

            try
            {
                creditCardValidator.Validate(creditCardNumber);
                throw new Exception(creditCardNumber + " should be valid");
            }
            catch (CreditCardValidationException)
            {
                // ok: credit card number is invalid
            }
        }

        private void NullReferenceExceptionTestForIbanValidation(string iban)
        {
            try
            {
                ibanValidator.Validate(iban);

                throw new Exception("NullReferenceExceptionTestForIbanValidation(" + iban + ") should have thrown a NullReferenceException");
            }
            catch (NullReferenceException)
            {
                // ok: iban is null/empty
            }
        }

        private void ArgumentExceptionTestForIbanValidation(string iban)
        {
            try
            {
                ibanValidator.Validate(iban);

                throw new Exception("ArgumentExceptionTestForIbanValidation(" + iban + ") should have thrown a ArgumentException");
            }
            catch (ArgumentException)
            {
                // ok: iban is invalid
            }
        }

        private void InvalidIbanTest(string iban)
        {
            Assert.IsNotNull(iban);
            Assert.IsTrue(iban.Length > 0);

            try
            {
                ibanValidator.Validate(iban);

                throw new Exception("iban " + iban + ") should be invalid");
            }
            catch (IbanValidationException)
            {
                // ok: iban is invalid
            }
        }

        private void NullReferenceExceptionTest(string identityType, string identityId)
        {
            try
            {
                identityValidator.Validate(identityType, identityId);

                throw new Exception("NullReferenceExceptionTest(" + identityType + "/" + identityId + ") should have thrown a NullReferenceException");
            }
            catch (NullReferenceException)
            {
                // ok: identity type and/or identity id is null/empty
            }
        }

        private void ArgumentExceptionTestForIdentityValidation(string identityType, string identityId)
        {
            try
            {
                identityValidator.Validate(identityType, identityId);

                throw new Exception("ArgumentExceptionTestForIdentityValidation(" + identityType + "/" + identityId + ") should have thrown a ArgumentException");
            }
            catch (ArgumentException)
            {
                // ok: personal identity type and/or id is invalid
            }
        }


        private void InvalidPersonalIdentityTest(string identityType, string identityId)
        {
            Assert.IsNotNull(identityType);
            Assert.IsNotNull(identityId);
            Assert.IsTrue(identityType.Length > 0);
            Assert.IsTrue(identityId.Length > 0);

            try
            {
                identityValidator.Validate(identityType, identityId);

                throw new Exception("identity " + identityType + "/" + identityId + ") should be invalid");
            }
            catch (IdentityValidationException)
            {
                // ok: personal identity type and/or id is valid
            }
        }

    }
}
