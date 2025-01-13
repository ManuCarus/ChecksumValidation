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
using System.Reflection;
using System.Runtime.InteropServices;

namespace ChecksumValidation.ChecksumClient.Proxy
{
    internal class ComProxy : IProxy
    {
        // private constants
        private const string cDefaultBankDirectory = ".";

        // private members
        private ParameterSet parameterSet;
        private TraceManager traceManager;
        private Type comServerType;
        private object comServer;

        // ctor
        internal ComProxy(ParameterSet parameterSet, TraceManager traceManager)
        {
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager not set!");

            this.parameterSet = parameterSet;
            this.traceManager = traceManager;

            // bank directory
            string bankDirectory = parameterSet.BankDirectory;
            if (String.IsNullOrEmpty(bankDirectory)) bankDirectory = cDefaultBankDirectory;

            // com server
            comServerType = Type.GetTypeFromProgID("ChecksumValidation.ChecksumServer.Server", true);
            comServer = Activator.CreateInstance(comServerType);

            comServerType.InvokeMember("SetBankDirectory", BindingFlags.InvokeMethod, null, comServer, new object[] { bankDirectory });
        }

        // bank account validation
        public string LoadBankDirectory()
        {
            try
            {
                traceManager.TraceLine("command: LoadBankDirectory()", TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("LoadBankDirectory", BindingFlags.InvokeMethod, null, comServer, null);
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return CommandHandler.cResultOk;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        public string ValidateBankAccount(string blz, string account)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: ValidateBankAccount(\"{0}\",\"{1}\")", blz, account), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("ValidateBankAccount", BindingFlags.InvokeMethod, null, comServer, new object[] { blz, account });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return CommandHandler.cResultOk;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        public string FormatBlz(string blz)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: FormatBlz(\"{0}\")", blz), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("FormatBlz", BindingFlags.InvokeMethod, null, comServer, new object[] { blz });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return (string)objResult;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        // iban validation
        public string ValidateIban(string iban)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: ValidateIban(\"{0}\")", iban), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("ValidateIban", BindingFlags.InvokeMethod, null, comServer, new object[] { iban });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return CommandHandler.cResultOk;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        public string FormatIban(string iban)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: FormatIban(\"{0}\")", iban), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("FormatIban", BindingFlags.InvokeMethod, null, comServer, new object[] { iban });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return (string)objResult;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        public string ToIban(string blz, string account)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: ToIban(\"{0}\",\"{1}\")", blz, account), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("ToIban", BindingFlags.InvokeMethod, null, comServer, new object[] { blz, account });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return (string)objResult;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        // credit card validation
        public string ValidateCreditCard(string creditCardNumber)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: ValidateCreditCard(\"{0}\")", creditCardNumber), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("ValidateCreditCard", BindingFlags.InvokeMethod, null, comServer, new object[] { creditCardNumber });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return CommandHandler.cResultOk;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        public string GetCreditCardType(string creditCardNumber)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: GetCreditCardType(\"{0}\")", creditCardNumber), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("GetCreditCardType", BindingFlags.InvokeMethod, null, comServer, new object[] { creditCardNumber });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return (string)objResult;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        // identity validation
        public string ValidateGermanIdentityCard(string identityId)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: ValidateGermanIdentityCard(\"{0}\")", identityId), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("ValidateGermanIdentityCard", BindingFlags.InvokeMethod, null, comServer, new object[] { identityId });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return CommandHandler.cResultOk;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        public string ValidateGermanPassport(string identityId)
        {
            try
            {
                traceManager.TraceLine(String.Format("command: ValidateGermanPassport(\"{0}\")", identityId), TraceManager.VerboseMode.Verbose);
                object objResult = comServerType.InvokeMember("ValidateGermanPassport", BindingFlags.InvokeMethod, null, comServer, new object[] { identityId });
                traceManager.TraceLine(String.Format("result: {0}", (objResult == null) ? CommandHandler.cResultOk : (string)objResult), TraceManager.VerboseMode.Verbose);

                return CommandHandler.cResultOk;
            }
            catch (Exception ex)
            {
                TraceException(ex);
                throw ex;
            }
        }

        private void TraceException(Exception ex)
        {
            traceManager.TraceLine(ex.Message, TraceManager.VerboseMode.None);

            if (ex.InnerException != null)
            {
                traceManager.TraceLine(ex.InnerException.Message, TraceManager.VerboseMode.None);
            }
        }
    }
}
