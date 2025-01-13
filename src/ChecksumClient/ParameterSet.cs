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
using System.IO;
using System.Security.Cryptography;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumClient
{
    internal sealed class ParameterSet
    {
        // allowed modes
        internal enum CommunicationMode { InProc, Tcp, Soap, Com };
        internal enum UserInterfaceMode { Console, Gui };

        // allowed ports
        private static ushort cMinPort = 49152;
        private static ushort cMaxPort = 65535;

        // tcp defaults
        internal static string cDefaultTcpServer = "localhost";
        internal static ushort cDefaultTcpPort = 65535;

        // command line options
        private const string cInproc = "-inproc";
        private const string cTcp = "-tcp";
        private const string cSoap = "-soap";
        private const string cCom = "-com";
        private const string cConsole = "-console";
        private const string cGui = "-gui";
        private const string cSecure = "-secure";
        private const string cPassword = "-password";
        private const string cVerbose = "-verbose";
        private const string cVeryVerbose = "--verbose";
        private const string cVeryVeryVerbose = "---verbose";
        private const string cLicence = "-licence";
        private const string cLicense = "-license";
        private const string cGpl = "-gpl";
        private const string cSilent = "-silent";
        private const string cHelp = "-help";

        internal const char cOptionDelimitor = ':';

        // private members
        private CommunicationMode communicationMode;
        private UserInterfaceMode userInterfaceMode;
        private TraceManager.VerboseMode verboseMode;
        private bool licence;
        private bool silent;
        private bool help;
        private string command;
        private string tcpServer;
        private ushort tcpPort;
        private string soapEndpoint;
        private string bankDirectory;

        // ctor
        internal ParameterSet()
        {
            communicationMode = CommunicationMode.InProc;
            userInterfaceMode = UserInterfaceMode.Console;
            verboseMode = TraceManager.VerboseMode.None;
            licence = false;
            silent = false;
            help = false;
            command = String.Empty;
            tcpServer = String.Empty;
            tcpPort = 0;
            soapEndpoint = String.Empty;
            bankDirectory = String.Empty;
        }

        // get/set properties
        internal bool RequiresSecureConnection
        {
            get { return ((communicationMode == CommunicationMode.Tcp) || (communicationMode == CommunicationMode.Soap)); }
        }

        internal CommunicationMode Communication
        {
            get { return communicationMode; }
        }

        internal UserInterfaceMode UserInterface
        {
            get { return userInterfaceMode; }
        }

        internal TraceManager.VerboseMode Verbose
        {
            get { return verboseMode; }
        }

        internal string Command
        {
            get { return command; }
        }

        internal string TcpServer
        {
            get { return tcpServer; }
        }

        internal ushort TcpPort
        {
            get { return tcpPort; }
        }

        internal string SoapEndpoint
        {
            get { return soapEndpoint; }
            set { soapEndpoint = value; }
        }

        internal string BankDirectory
        {
            get { return bankDirectory; }
            set { bankDirectory = value; }
        }

        internal bool Licence
        {
            get { return licence; }
        }

        internal bool Silent
        {
            get { return silent; }
        }

        internal bool Help
        {
            get { return help; }
        }

        // look ahead for requested help 
        internal static void LookAheadCommandLineParameters(string[] args, out bool licence, out bool silent, out bool help)
        {
            if (args == null) throw new NullReferenceException("arguments not set!");

            licence = false;
            silent = false;
            help = false;

            foreach (string arg in args)
            {
                if (String.Compare(arg, cLicence, true) == 0) licence = true;
                if (String.Compare(arg, cLicense, true) == 0) licence = true;
                if (String.Compare(arg, cGpl, true) == 0) licence = true;
                if (String.Compare(arg, cSilent, true) == 0) silent = true;
                if (String.Compare(arg, cHelp, true) == 0) help = true;
            }
        }

        // parse command line
        internal void ParseCommandLine(string[] args, SecurityController securityController)
        {
            if (args == null) throw new NullReferenceException("arguments not set!");
            if (securityController == null) throw new NullReferenceException("security controller not set!");

            foreach (string arg in args)
            {
                if (arg.Equals(cInproc, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -inproc
                    this.communicationMode = CommunicationMode.InProc;
                }
                else if (arg.Equals(cTcp, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -tcp
                    this.communicationMode = CommunicationMode.Tcp;
                }
                else if (arg.Equals(cSoap, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -soap
                    this.communicationMode = CommunicationMode.Soap;
                }
                else if (arg.Equals(cCom, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -com
                    this.communicationMode = CommunicationMode.Com;
                }
                else if (arg.Equals(cConsole, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -console
                    this.userInterfaceMode = UserInterfaceMode.Console;
                }
                else if (arg.Equals(cGui, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -gui
                    this.userInterfaceMode = UserInterfaceMode.Gui;
                }
                else if (arg.Equals(cSecure, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -secure
                    securityController.IsSecureConnection = true;
                }
                else if (arg.StartsWith(cPassword + cOptionDelimitor, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -password:pwd
                    string password = GetOptionValue(arg);
                    string verificationPassword = (string)password.Clone();

                    securityController.SetCipherKey(ref password, ref verificationPassword);
                }
                else if (arg.Equals(cVerbose, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -verbose
                    this.verboseMode = TraceManager.VerboseMode.Verbose;
                }
                else if (arg.Equals(cVeryVerbose, StringComparison.CurrentCultureIgnoreCase))
                {
                    // --verbose
                    this.verboseMode = TraceManager.VerboseMode.VeryVerbose;
                }
                else if (arg.Equals(cVeryVeryVerbose, StringComparison.CurrentCultureIgnoreCase))
                {
                    // ---verbose
                    this.verboseMode = TraceManager.VerboseMode.VeryVeryVerbose;
                }
                else if (arg.Equals(cLicence, StringComparison.CurrentCultureIgnoreCase) || 
                         arg.Equals(cLicense, StringComparison.CurrentCultureIgnoreCase) ||
                         arg.Equals(cGpl, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -licence or -license or -gpl
                    this.licence = true;
                }
                else if (arg.Equals(cSilent, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -silent
                    this.silent = true;
                }
                else if (arg.Equals(cHelp, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -help
                    this.help = true;
                }
                else if (arg.StartsWith("-", StringComparison.CurrentCultureIgnoreCase))
                {
                    // unknown option
                    throw new ArgumentException("syntax error: unknown command line parameter!");
                }
                else
                {
                    // command
                    if ((this.Command == null) || String.IsNullOrEmpty(this.Command)) this.command = arg;
                    else throw new ArgumentException("syntax error: multiple commands specified!");
                }
            }

            if ((this.Communication == CommunicationMode.Tcp) || (this.Communication == CommunicationMode.Soap))
            {
                securityController.SetSecuritySettings();
            }

            SetTcpSettings();
            SetSoapSettings();
            SetBankSettings();
        }

        // helper: split "-option:value"
        private string GetOptionValue(string arg)
        {
            if (String.IsNullOrEmpty(arg)) throw new NullReferenceException("argument not set!");

            string optionValue = arg.Substring(arg.IndexOf(cOptionDelimitor) + 1); // e.g. "-password:ABC:123:():!"
            if (String.IsNullOrEmpty(optionValue)) throw new ArgumentException(String.Format("syntax error: no value specified for option ({0})!", arg));
            return optionValue;
        }

        // tcp settings
        private void SetTcpSettings()
        {
            string strTcpServer = null;
            string strTcpPort = null;

            try
            {
                strTcpServer = ConfigurationManager.AppSettings["tcp-server"];
                strTcpPort = ConfigurationManager.AppSettings["tcp-port"];
            }
            catch (ConfigurationErrorsException)
            {
                strTcpServer = cDefaultTcpServer;
                strTcpPort = cDefaultTcpPort.ToString();
            }
            finally
            {
                if (strTcpServer == null) strTcpServer = cDefaultTcpServer;
                if (strTcpPort == null) strTcpPort = cDefaultTcpPort.ToString();
            }

            try
            {
                this.tcpServer = strTcpServer;
                this.tcpPort = ushort.Parse(strTcpPort);
            }
            catch (FormatException)
            {
                throw new ArgumentException(String.Format("syntax error: invalid port format ({0})!", strTcpPort));
            }
            catch (OverflowException)
            {
                throw new ArgumentException(String.Format("syntax error: port {0} not in range {1}..{2}!", strTcpPort, cMinPort.ToString(), cMaxPort.ToString()));
            }
        }

        // soap settings
        private void SetSoapSettings()
        {
            this.soapEndpoint = ConfigurationManager.AppSettings["soap-endpoint"];
        }

        // bank settings
        private void SetBankSettings()
        {
            this.bankDirectory = ConfigurationManager.AppSettings["bank-directory"];
            if (this.bankDirectory == null) this.bankDirectory = ".";
            if (this.bankDirectory.CompareTo(".") == 0) this.bankDirectory = Directory.GetCurrentDirectory();
        }

        // validate parameter set
        internal void Validate(SecurityController securityController)
        {
            if (securityController == null) throw new NullReferenceException("security controller not set!");
            
            // command (only for -console)
            if ((this.UserInterface == UserInterfaceMode.Console) && 
                ((this.Command == null) || String.IsNullOrEmpty(this.Command))) throw new ArgumentException("syntax error: no command specified!");

            // tcp server: security settings (only for -console)
            if (this.Communication == CommunicationMode.Tcp)
            {
                if ((this.UserInterface == UserInterfaceMode.Console))
                {
                    if (this.RequiresSecureConnection && !securityController.IsSecureConnection && !securityController.IsPasswordSet) throw new ArgumentException("security error: no passphrase set for insecure connection");
                }

                // port 
                if ((this.TcpPort < cMinPort) || (this.TcpPort > cMaxPort)) throw new ArgumentException(String.Format("semantic error: port {0} not in range {1}..{2}!", this.TcpPort.ToString(), cMinPort.ToString(), cMaxPort.ToString()));

                // password (only for -console)
                if ((this.UserInterface == UserInterfaceMode.Console))
                {
                    securityController.Validate();
                }
            }
        }

    }
}
