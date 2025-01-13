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
using System.IO;
using ChecksumValidation.ChecksumClient.Proxy;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumClient
{
    internal class CommandHandler
    {
        internal const string cResultOk = "ok";

        internal static IProxy CreateProxy(SecurityController securityController, ParameterSet.CommunicationMode communicationMode, ParameterSet parameterSet, TraceManager traceManager)
        {
            if (securityController == null) throw new NullReferenceException("security controller not set!");
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager controller not set!");

            IProxy proxy;

            if (communicationMode == ParameterSet.CommunicationMode.InProc)
            {
                proxy = new Proxy.InProcProxy(parameterSet, traceManager);
            }
            else if (communicationMode == ParameterSet.CommunicationMode.Tcp)
            {
                proxy = new Proxy.TcpProxy(securityController, parameterSet, traceManager);
            }
            else if (communicationMode == ParameterSet.CommunicationMode.Soap)
            {
                proxy = new Proxy.SoapProxy(securityController, parameterSet, traceManager);
            }
            else if (communicationMode == ParameterSet.CommunicationMode.Com)
            {
                proxy = new Proxy.ComProxy(parameterSet, traceManager);
            }
            else
            {
                throw new Exception("invalid communication mode!");
            }

            return proxy;
        }

        internal static string HandleCommandThroughCommunicationChannel(IProxy proxy, string command)
        {
            return HandleCommand(proxy, command);
        }

        private static string HandleCommand(IProxy proxy, string command)
        {
            if (proxy == null) throw new NullReferenceException("proxy not set!");
            if (String.IsNullOrEmpty(command)) throw new NullReferenceException("command not set!");

            // parse received command
            if (command.Equals(ChecksumValidation.CommandHandler.cCmdCache, StringComparison.CurrentCulture))
            {
                string result = proxy.LoadBankDirectory();
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdAccount, StringComparison.CurrentCulture))
            {
                string blz;
                string account;
                ChecksumValidation.CommandHandler.SplitAccountData(command, out blz, out account);

                string result = proxy.ValidateBankAccount(blz, account);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdFormatBlz, StringComparison.CurrentCulture))
            {
                string blz = ChecksumValidation.CommandHandler.SplitFormatBlzData(command);
                string result = proxy.FormatBlz(blz);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdIban, StringComparison.CurrentCulture))
            {
                string iban = ChecksumValidation.CommandHandler.SplitIbanData(command);
                string result = proxy.ValidateIban(iban);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdToIban, StringComparison.CurrentCulture))
            {
                string blz;
                string account;
                ChecksumValidation.CommandHandler.SplitToIbanData(command, out blz, out account);

                string result = proxy.ToIban(blz, account);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdFormatIban, StringComparison.CurrentCulture))
            {
                string iban = ChecksumValidation.CommandHandler.SplitFormatIbanData(command);
                string result = proxy.FormatIban(iban);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdIdentity, StringComparison.CurrentCulture))
            {
                string identityId = ChecksumValidation.CommandHandler.SplitIdentityData(command);
                string result = proxy.ValidateGermanIdentityCard(identityId);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdPassport, StringComparison.CurrentCulture))
            {
                string identityId = ChecksumValidation.CommandHandler.SplitPassportData(command);
                string result = proxy.ValidateGermanPassport(identityId);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdCreditCard, StringComparison.CurrentCulture))
            {
                string creditCardNumber = ChecksumValidation.CommandHandler.SplitCreditCardData(command);
                string result = proxy.ValidateCreditCard(creditCardNumber);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdGetCreditCardType, StringComparison.CurrentCulture))
            {
                string creditCardNumber = ChecksumValidation.CommandHandler.SplitToCreditCardInstituteData(command);
                string result = proxy.GetCreditCardType(creditCardNumber);
                return result;
            }
            else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdStop, StringComparison.CurrentCulture))
            {
                if (proxy.GetType() == typeof(TcpProxy))
                {
                    TcpProxy tcpProxy = (TcpProxy)proxy;
                    string result = tcpProxy.Stop();
                    return result;
                }
                else
                {
                    throw new ChecksumException("argument:1021", "command not supported!");
                }
            }
            else
            {
                throw new ChecksumException("argument:1021", "command not supported!");
            }

        }

    }
}
