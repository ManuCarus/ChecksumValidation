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
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumClient.Proxy
{
    internal class TcpProxy : IProxy, IDisposable
    {
        // private members
        private SecurityController securityController;
        private ParameterSet parameterSet;
        private TraceManager traceManager;
        private TcpClient tcpClient;
        private bool disposed = false;

        // ctor
        internal TcpProxy(SecurityController securityController, ParameterSet parameterSet, TraceManager traceManager)
        {
            if (securityController == null) throw new NullReferenceException("security controller not set!");
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager not set!");

            this.securityController = securityController;
            this.parameterSet = parameterSet;
            this.traceManager = traceManager;
            this.tcpClient = null;
        }

        // dtor
        ~TcpProxy()
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
                if (tcpClient != null) tcpClient.Close();
                tcpClient = null;
            }

            this.disposed = true;
        }

        // helper
        public string SendCommand(string command)
        {
            if (String.IsNullOrEmpty(command)) throw new NullReferenceException("command not set!");

            traceManager.TraceLine(String.Format("command: {0}", command), TraceManager.VerboseMode.Verbose);

            // whenever you do something with this class, check to see if it has been disposed
            if (this.disposed) throw new ObjectDisposedException("TcpProxy");

            // create socket (if not already set)
            if (tcpClient == null) tcpClient = new TcpClient(parameterSet.TcpServer, parameterSet.TcpPort);
            if (!tcpClient.Connected) tcpClient.Connect(parameterSet.TcpServer, parameterSet.TcpPort);

            // send client request
            securityController.Send(tcpClient, command);

            // read server response
            string response = securityController.Receive(tcpClient);

            traceManager.TraceLine(String.Format("result: {0}", response), TraceManager.VerboseMode.Verbose);

            return response;
        }

        // bank account validation
        public string LoadBankDirectory()
        {
            string command = ChecksumValidation.CommandHandler.cCmdCache;
            return SendCommand(command);
        }

        public string ValidateBankAccount(string blz, string account)
        {
            string command = ChecksumValidation.CommandHandler.cCmdAccount + account + "/" + blz;
            return SendCommand(command);
        }

        public string FormatBlz(string blz)
        {
            string command = ChecksumValidation.CommandHandler.cCmdFormatBlz + blz;
            return SendCommand(command);
        }

        // iban validation
        public string ValidateIban(string iban)
        {
            string command = ChecksumValidation.CommandHandler.cCmdIban + iban;
            return SendCommand(command);
        }

        public string FormatIban(string iban)
        {
            string command = ChecksumValidation.CommandHandler.cCmdFormatIban + iban;
            return SendCommand(command);
        }

        public string ToIban(string blz, string account)
        {
            string command = ChecksumValidation.CommandHandler.cCmdToIban + account + "/" + blz;
            return SendCommand(command);
        }

        // credit card validation
        public string ValidateCreditCard(string creditCardNumber)
        {
            string command = ChecksumValidation.CommandHandler.cCmdCreditCard + creditCardNumber;
            return SendCommand(command);
        }

        public string GetCreditCardType(string creditCardNumber)
        {
            string command = ChecksumValidation.CommandHandler.cCmdGetCreditCardType + creditCardNumber;
            return SendCommand(command);
        }

        // identity validation
        public string ValidateGermanIdentityCard(string identityId)
        {
            string command = ChecksumValidation.CommandHandler.cCmdIdentity + identityId;
            return SendCommand(command);
        }

        public string ValidateGermanPassport(string identityId)
        {
            string command = ChecksumValidation.CommandHandler.cCmdPassport + identityId;
            return SendCommand(command);
        }

        // stop server (command exclusively for tcp server)
        public string Stop()
        {
            string command = ChecksumValidation.CommandHandler.cCmdStop;
            string response;
            try { response = SendCommand(command); }
            catch (IOException) { response = CommandHandler.cResultOk; } // [System.IO.IOException] = {"Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."}
            return response;
        }

    }
}
