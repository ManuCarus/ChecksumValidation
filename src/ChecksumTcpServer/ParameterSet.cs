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
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumTcpServer
{
    internal sealed class ParameterSet
    {
        // allowed ports
        private static ushort cMinPort = 49152;
        private static ushort cMaxPort = 65535;

        // tcp defaults
        private static ushort cDefaultTcpPort = 65535;

        // command line options
        private const string cPort = "-port";
        private const string cSecure = "-secure";
        private const string cPassword = "-password";
        private const string cTrace = "-trace";
        private const string cError = "-error";
        private const string cVerbose1 = "-verbose";
        private const string cVerbose2 = "--verbose";
        private const string cVerbose3 = "---verbose";
        private const string cLicence = "-licence";
        private const string cLicense = "-license";
        private const string cGpl = "-gpl";
        private const string cSilent = "-silent";
        private const string cHelp = "-help";

        internal const char cOptionDelimitor = ':';

        // configuration entries
        private const string cBaseDirBankDirectory = ".";

        // private members
        private ushort tcpPort;
        private string strBaseDirBankDirectory;
        private TraceManager.VerboseMode verbose;
        private string traceFile;
        private string errorFile;
        private bool licence;
        private bool silent;
        private bool help;

        // ctor
        internal ParameterSet()
        {
            tcpPort = 0;
            strBaseDirBankDirectory = String.Empty;
            verbose = TraceManager.VerboseMode.None;
            traceFile = String.Empty;
            errorFile = String.Empty;
            licence = false;
            silent = false;
            help = false;
        }

        // get/set properties
        internal ushort TcpPort
        {
            get { return tcpPort; }
        }

        internal string BaseDirBankDirectory
        {
            get { return strBaseDirBankDirectory; }
        }

        internal string Trace
        {
            get { return traceFile; }
        }

        internal string Error
        {
            get { return errorFile; }
        }

        internal TraceManager.VerboseMode Verbose
        {
            get { return verbose; }
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

        // command line parameters look ahead
        internal static void LookAheadCommandLineParameters(string[] args, out bool licence, out bool silent, out bool help)
        {
            if (args == null) throw new ArgumentNullException("args");

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

        // parse command line parameters
        internal void ParseCommandLine(string[] args, SecurityController securityController)
        {
            // validation
            if (args == null) throw new NullReferenceException("arguments not set!");
            if (securityController == null) throw new NullReferenceException("security controller not set!");

            // parsing
            foreach (string arg in args)
            {
                if (arg.Equals(cSecure, StringComparison.CurrentCultureIgnoreCase))
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
                else if (arg.StartsWith(cPort + cOptionDelimitor, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -port:port
                    string port = GetOptionValue(arg);
                    this.tcpPort = ConvertTcpPort(port);
                }
                else if (arg.StartsWith(cTrace + cOptionDelimitor, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -trace:file
                    string traceFile = GetOptionValue(arg);
                    this.traceFile = traceFile;
                }
                else if (arg.StartsWith(cError + cOptionDelimitor, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -error:file
                    string errorFile = GetOptionValue(arg);
                    this.errorFile = errorFile;
                }
                // -verbose
                else if (arg.Equals(cVerbose1, StringComparison.CurrentCultureIgnoreCase)) this.verbose = TraceManager.VerboseMode.Verbose;
                else if (arg.Equals(cVerbose2, StringComparison.CurrentCultureIgnoreCase)) this.verbose = TraceManager.VerboseMode.VeryVerbose;
                else if (arg.Equals(cVerbose3, StringComparison.CurrentCultureIgnoreCase)) this.verbose = TraceManager.VerboseMode.VeryVeryVerbose;
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
                // -help
                else if (arg.Equals(cHelp, StringComparison.CurrentCultureIgnoreCase)) this.help = true;
                else 
                {
                    // unknown option
                    throw new ArgumentException("syntax error: unknown command line parameter!");
                }
            }

            securityController.SetSecuritySettings();
            SetTcpSettings();
            SetBankSettings();
        }

        // tcp settings
        private void SetTcpSettings()
        {
            if (this.TcpPort == 0)
            {
                string strTcpPort = null;

                try
                {
                    strTcpPort = ConfigurationManager.AppSettings["tcp-port"];
                }
                catch (ConfigurationErrorsException)
                {
                    strTcpPort = cDefaultTcpPort.ToString();
                }
                finally
                {
                    if (strTcpPort == null) strTcpPort = cDefaultTcpPort.ToString();
                }

                this.tcpPort = ConvertTcpPort(strTcpPort);
            }
        }

        private ushort ConvertTcpPort(string port)
        {
            try
            {
                return ushort.Parse(port);
            }
            catch (FormatException)
            {
                throw new ArgumentException(String.Format("syntax error: invalid port format ({0})!", port));
            }
            catch (OverflowException)
            {
                throw new ArgumentException(String.Format("syntax error: port {0} not in range {1}..{2}!", port, cMinPort.ToString(), cMaxPort.ToString()));
            }
        }
        
        // bank settings
        private void SetBankSettings()
        {
            string strBaseDir = ConfigurationManager.AppSettings["bank-directory"];

            if (strBaseDir == null) strBaseDir = cBaseDirBankDirectory;
            if (!strBaseDir.EndsWith("\\")) strBaseDir += "\\";

            this.strBaseDirBankDirectory = strBaseDir;
        }

        // validate parameter set
        internal void Validate(SecurityController securityController)
        {
            if (securityController == null) throw new NullReferenceException("security controller not set!");

            // server ip/name: no validation (errors will occur when creating a socket at a later time)

            // port 
            if ((this.tcpPort < cMinPort) || (this.tcpPort > cMaxPort)) throw new ArgumentException(String.Format("semantic error: port {0} not in range {1}..{2}", this.tcpPort.ToString(), cMinPort.ToString(), cMaxPort.ToString()));

            // password
            securityController.Validate();

            // output files
            EnsureFileIsCreatable(this.Trace);
            EnsureFileIsCreatable(this.Error);

            // configuration
            EnsureDirectoryExists(this.BaseDirBankDirectory);
        }

        // helper: split "-option:value"
        private string GetOptionValue(string arg)
        {
            if (String.IsNullOrEmpty(arg)) throw new NullReferenceException("option not set!");

            string optionValue = arg.Substring(arg.IndexOf(cOptionDelimitor) + 1); // e.g. "c:\" for "-trace:c:\application.trace.txt"
            if (String.IsNullOrEmpty(optionValue)) throw new ArgumentException(String.Format("syntax error: no value specified for option ({0})!", arg));
            return optionValue;
        }

        // helper: check if file can be created
        private void EnsureFileIsCreatable(string file)
        {
            if (String.IsNullOrEmpty(file)) return;
            if (file.Equals("stdout", StringComparison.CurrentCultureIgnoreCase)) return;

            FileStream fileStream = null;

            try
            {
                fileStream = File.Create(file);
            }
            catch (UnauthorizedAccessException uaex) { throw new ArgumentException(String.Format("validation error: unauthorized access to file '{0}'", file), uaex); }
            catch (ArgumentNullException anex) { throw new ArgumentException("validation error: no file specified", anex); }
            catch (ArgumentException aex) { throw new ArgumentException(String.Format("validation error: invalid name of file '{0}'", file), aex); }
            catch (PathTooLongException ptlex) { throw new ArgumentException(String.Format("validation error: path of file '{0}' too long", file), ptlex); }
            catch (DirectoryNotFoundException dnfex) { throw new ArgumentException(String.Format("validation error: directory of file '{0}' not found", file), dnfex); }
            catch (IOException ioex) { throw new ArgumentException(String.Format("validation error: i/o exception when creating file '{0}'", file), ioex); }
            catch (NotSupportedException nsex) { throw new ArgumentException(String.Format("validation error: not supported exception for file '{0}'", file), nsex); }
            finally
            {
                if (fileStream != null) fileStream.Close();
                File.Delete(file);
            }
        }

        // helper: check if directory exists
        private void EnsureDirectoryExists(string dir)
        {
            if (String.IsNullOrEmpty(dir)) throw new NullReferenceException("directory not set!");
            if (!Directory.Exists(dir)) throw new ConfigurationErrorsException(String.Format("validation error: directory {0} does not exist", dir));
        }
    }
}
