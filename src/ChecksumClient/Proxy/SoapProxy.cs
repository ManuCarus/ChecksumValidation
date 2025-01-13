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
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumClient.Proxy
{
    internal class SoapProxy : IProxy, IDisposable
    {
        // private members
        private SecurityController securityController;
        private ParameterSet parameterSet;
        private TraceManager traceManager;
        private ChecksumValidation.ChecksumClient.ChecksumValidationSoapServer.ChecksumValidation soapServer;
        private bool disposed;

        // ctor
        internal SoapProxy(SecurityController securityController, ParameterSet parameterSet, TraceManager traceManager)
        {
            if (securityController == null) throw new NullReferenceException("security controller not set!");
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager not set!");

            this.securityController = securityController;
            this.parameterSet = parameterSet;
            this.traceManager = traceManager;

            soapServer = new ChecksumValidation.ChecksumClient.ChecksumValidationSoapServer.ChecksumValidation();
            soapServer.Url = parameterSet.SoapEndpoint;
            soapServer.SecuritySettingsValue = new ChecksumValidation.ChecksumClient.ChecksumValidationSoapServer.SecuritySettings();
            soapServer.SecuritySettingsValue.secureConnection = (securityController.IsSecureConnection ? "true" : "false");

            disposed = false;
        }

        // dtor
        ~SoapProxy()
        {
            Dispose(false);
        }

        // IDisposable
        public void Dispose()
        {
            Dispose(true);
            
            // take yourself off the Finalization queue to prevent finalization code for this object
            // from executing a second time.
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (soapServer != null) soapServer.Dispose();
                soapServer = null;
            }

            this.disposed = true;
        }

        // bank account validation
        public string LoadBankDirectory()
        {
            throw new Exception("bank directory cannot be cached since soap is a stateless protocol!");
        }

        public string ValidateBankAccount(string blz, string account)
        {
            soapServer.ValidateBankAccount(blz, account);
            return CommandHandler.cResultOk;
        }

        public string FormatBlz(string blz)
        {
            return soapServer.FormatBlz(blz);
        }

        // iban validation
        public string ValidateIban(string iban)
        {
            soapServer.ValidateIban(iban);
            return CommandHandler.cResultOk;
        }

        public string FormatIban(string iban)
        {
            return soapServer.FormatIban(iban);
        }

        public string ToIban(string blz, string account)
        {
            return soapServer.ToIban(blz, account);
        }

        // credit card validation
        public string ValidateCreditCard(string creditCardNumber)
        {
            soapServer.ValidateCreditCard(creditCardNumber);
            return CommandHandler.cResultOk;
        }

        public string GetCreditCardType(string creditCardNumber)
        {
            return soapServer.GetCreditCardType(creditCardNumber);
        }

        // identity validation
        public string ValidateGermanIdentityCard(string identityId)
        {
            soapServer.ValidateGermanIdentityCard(identityId);
            return CommandHandler.cResultOk;
        }

        public string ValidateGermanPassport(string identityId)
        {
            soapServer.ValidateGermanPassport(identityId);
            return CommandHandler.cResultOk;
        }

    }
}
