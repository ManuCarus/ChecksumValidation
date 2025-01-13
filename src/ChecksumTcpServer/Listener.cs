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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumTcpServer
{
    internal sealed class Listener
    {
        private const string cResponseOk = "ok";
        private const string cResponseError = "error:[{0}]";

        private Queue threads;
        private SecurityController securityController;
        private ParameterSet parameterSet;
        private TraceManager traceManager;
        private TextWriter errorStream;

        private BankAccountValidation.BankAccountValidator bankAccountValidator;
        private IbanValidation.IbanValidator ibanValidator;
        private IdentityValidation.IdentityValidator identityValidator;
        private CreditCardValidation.CreditCardValidator creditCardValidator;

        // thread parameter structure
        internal class ListenerThreadParameters
        {
            internal TcpListener server;
            internal TcpClient tcpClient;
            internal SecurityController securityController;
            internal BankAccountValidation.BankAccountValidator bankAccountValidator;
            internal IbanValidation.IbanValidator ibanValidator;
            internal IdentityValidation.IdentityValidator identityValidator;
            internal CreditCardValidation.CreditCardValidator creditCardValidator;
            internal TraceManager traceManager;
            internal TextWriter errorStream;
          }

        internal Listener(SecurityController securityController, ParameterSet parameterSet, TraceManager traceManager, TextWriter errorStream)
        {
            this.threads = new Queue();
            this.securityController = securityController;
            this.parameterSet = parameterSet;
            this.traceManager = traceManager;
            this.errorStream = errorStream;

            this.bankAccountValidator = new BankAccountValidation.BankAccountValidator(traceManager, parameterSet.BaseDirBankDirectory);
            this.ibanValidator = new IbanValidation.IbanValidator(traceManager);
            this.identityValidator = new IdentityValidation.IdentityValidator(traceManager);
            this.creditCardValidator = new CreditCardValidation.CreditCardValidator(traceManager);
        }

        internal void Listen()
        {
            TcpListener server = null;

            try
            {
                traceManager.TraceLine(String.Format("starting server on port {0} at {1} {2}...", parameterSet.TcpPort.ToString(), DateTime.Now.ToString("dd.MM.yyyy"), DateTime.Now.ToString("HH:mm:ss")), TraceManager.VerboseMode.None);

                server = new TcpListener(IPAddress.Any, parameterSet.TcpPort);
                server.Start();

                Listen(server);
            }
            finally
            {
                if (threads != null)
                {
                    for (int i = 0; i < threads.Count; i++)
                    {
                        Object entry = threads.Dequeue();
                        if (entry.GetType() != typeof(Thread)) throw new Exception(String.Format("type mismatch: queue item is of type '{0}'", entry.GetType().FullName));
                        Thread thread = (Thread)entry;
                        if (thread.IsAlive) 
                        {
                            if (!thread.Join(100)) thread.Abort();
                        }
                    }
                }

                if (server != null)
                {
                    server.Stop();
                    traceManager.TraceLine(String.Format("stopped server at {0} {1}...", DateTime.Now.ToString("dd.MM.yyyy"), DateTime.Now.ToString("HH:mm:ss")), TraceManager.VerboseMode.None);
                }
            }
        }

        private void Listen(TcpListener server)
        {
            if (server == null) throw new NullReferenceException("server not set!");

            // Enter the listening loop.
            while (true)
            {
                traceManager.TraceLine("waiting for requests...", TraceManager.VerboseMode.None);

                // blocking call to accept requests
                TcpClient tcpClient = server.AcceptTcpClient();

                // serve client (multithreaded)
                Thread thread = null;

                try
                {
                    // thread
                    thread = new Thread(new ParameterizedThreadStart(ServeClientThreadProc));
                    thread.Name = tcpClient.Client.RemoteEndPoint.ToString(); // thread name := "<client_hostname>:<client_port>"
                    threads.Enqueue(thread);

                    // parameter
                    ListenerThreadParameters threadParams = new ListenerThreadParameters();

                    threadParams.server = server;
                    threadParams.tcpClient = tcpClient;
                    threadParams.securityController = this.securityController;
                    threadParams.bankAccountValidator = this.bankAccountValidator;
                    threadParams.ibanValidator = this.ibanValidator;
                    threadParams.identityValidator = this.identityValidator;
                    threadParams.creditCardValidator = this.creditCardValidator;
                    threadParams.traceManager = this.traceManager;
                    threadParams.errorStream = this.errorStream;

                    // worker
                    thread.Start(threadParams);
                }
                catch
                {
                    if ((thread != null) && (thread.IsAlive))
                    {
                        if (!thread.Join(100)) thread.Abort();
                    }

                    throw;
                }
            }
        }

        // threading
        public static void ServeClientThreadProc(object param)
        {
            if (param == null) throw new NullReferenceException("param not set!");
            if (param.GetType() != typeof(ListenerThreadParameters)) throw new Exception(String.Format("type mismatch: param is of type '{0}'", param.GetType().FullName));

            ListenerThreadParameters threadParams = (ListenerThreadParameters)param;

            threadParams.traceManager.TraceLine(String.Format("client {0} connected...", threadParams.tcpClient.Client.RemoteEndPoint.ToString()), TraceManager.VerboseMode.None);

            while (true)
            {
                try
                {
                    // retrieve command
                    string command = threadParams.securityController.Receive(threadParams.tcpClient);

                    threadParams.traceManager.TraceLine(String.Format("received request '{0}' from client {1}", command, threadParams.tcpClient.Client.RemoteEndPoint.ToString()), TraceManager.VerboseMode.Verbose);
                    threadParams.traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

                    string response = String.Empty;

                    // parse received command
                    if (command.Equals(ChecksumValidation.CommandHandler.cCmdCache, StringComparison.CurrentCulture))
                    {
                        // syntax: "cache"
                        threadParams.bankAccountValidator.Load();
                        response = cResponseOk;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdAccount, StringComparison.CurrentCulture))
                    {
                        string blz;
                        string account;
                        ChecksumValidation.CommandHandler.SplitAccountData(command, out blz, out account);

                        threadParams.bankAccountValidator.Validate(blz, account);
                        response = cResponseOk;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdFormatBlz, StringComparison.CurrentCulture))
                    {
                        string blz = ChecksumValidation.CommandHandler.SplitFormatBlzData(command);

                        string formattedBlz = threadParams.bankAccountValidator.FormatBlz(blz);
                        response = formattedBlz;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdIban, StringComparison.CurrentCulture))
                    {
                        string iban = ChecksumValidation.CommandHandler.SplitIbanData(command);

                        threadParams.ibanValidator.Validate(iban);
                        response = cResponseOk;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdToIban, StringComparison.CurrentCulture))
                    {
                        string blz;
                        string account;
                        ChecksumValidation.CommandHandler.SplitToIbanData(command, out blz, out account);

                        string iban = threadParams.ibanValidator.ToIban(blz, account);
                        response = iban;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdFormatIban, StringComparison.CurrentCulture))
                    {
                        string iban = ChecksumValidation.CommandHandler.SplitFormatIbanData(command);

                        string formattedIban = threadParams.ibanValidator.FormatIban(iban);
                        response = formattedIban;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdIdentity, StringComparison.CurrentCulture))
                    {
                        string identityId = ChecksumValidation.CommandHandler.SplitIdentityData(command);

                        threadParams.identityValidator.Validate(ChecksumValidation.IdentityValidation.IdentityValidator.IdentityType.GermanIdentityCard, identityId);
                        response = cResponseOk;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdPassport, StringComparison.CurrentCulture))
                    {
                        string identityId = ChecksumValidation.CommandHandler.SplitPassportData(command);

                        threadParams.identityValidator.Validate(ChecksumValidation.IdentityValidation.IdentityValidator.IdentityType.GermanPassport, identityId);
                        response = cResponseOk;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdCreditCard, StringComparison.CurrentCulture))
                    {
                        string creditCardNumber = ChecksumValidation.CommandHandler.SplitCreditCardData(command);

                        threadParams.creditCardValidator.Validate(creditCardNumber);
                        response = cResponseOk;
                    }
                    else if (command.StartsWith(ChecksumValidation.CommandHandler.cCmdGetCreditCardType, StringComparison.CurrentCulture))
                    {
                        string creditCardNumber = ChecksumValidation.CommandHandler.SplitToCreditCardInstituteData(command);

                        string creditCardInstitute = threadParams.creditCardValidator.GetCreditCardType(creditCardNumber);
                        response = creditCardInstitute;
                    }
                    else if (command.Equals(ChecksumValidation.CommandHandler.cCmdStop, StringComparison.CurrentCulture))
                    {
                        // syntax: "stop"
                        // not allowed from remote!
                        string serverIp = ((IPEndPoint)threadParams.server.Server.LocalEndPoint).Address.ToString();
                        string clientIp = ((IPEndPoint)threadParams.tcpClient.Client.RemoteEndPoint).Address.ToString();
                       
                        if (!clientIp.Equals(serverIp, StringComparison.CurrentCulture) &&
                            !clientIp.Equals(IPAddress.Loopback.ToString())) throw new ChecksumException("authorization:2001", "shutdown from remote client is not allowed!");

                        Environment.Exit(0);
                    }
                    else
                    {
                        throw new ChecksumException("argument:1021", "command not supported!");
                    }

                    threadParams.securityController.Send(threadParams.tcpClient, response);

                    threadParams.traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
                    threadParams.traceManager.TraceLine(String.Format("sent '{0}' to client {1}...", response, threadParams.tcpClient.Client.RemoteEndPoint.ToString()), TraceManager.VerboseMode.Verbose);
                }
                catch (ChecksumException cex)
                {
                    threadParams.errorStream.WriteLine("-".PadRight(80, '-'));
                    threadParams.errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss"));
                    threadParams.errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + String.Format("ChecksumException.Code = {0}", cex.Code));
                    threadParams.errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + cex.ToString());
                    if (cex.InnerException != null) threadParams.errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + cex.InnerException.ToString());

                    string serverResponse = String.Format(cResponseError, cex.Code);

                    threadParams.securityController.Send(threadParams.tcpClient, serverResponse);

                    threadParams.traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
                    threadParams.traceManager.TraceLine(String.Format("sent '{0}' to client {1}...", serverResponse, threadParams.tcpClient.Client.RemoteEndPoint.ToString()), TraceManager.VerboseMode.Verbose);
                }
                catch (Exception ex)
                {
                    if (!threadParams.tcpClient.Connected)
                    {
                        Thread.CurrentThread.Abort();
                        return;
                    }
                        
                    threadParams.errorStream.WriteLine("-".PadRight(80, '-'));
                    threadParams.errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss"));
                    threadParams.errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + ex.ToString());
                    if (ex.InnerException != null) threadParams.errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + ex.InnerException.ToString());

                    string serverResponse = String.Format(cResponseError, "internal:9999");

                    threadParams.securityController.Send(threadParams.tcpClient, serverResponse);

                    threadParams.traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);
                    threadParams.traceManager.TraceLine(String.Format("sent '{0}' to client {1}...", serverResponse, threadParams.tcpClient.Client.RemoteEndPoint.ToString()), TraceManager.VerboseMode.Verbose);
                }
            }
        }
    }
}
