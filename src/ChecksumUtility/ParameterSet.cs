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

namespace ChecksumValidation.ChecksumUtility
{
    internal sealed class ParameterSet
    {
        // command line options
        private const string cVerbose = "-verbose";
        private const string cLicence = "-licence";
        private const string cLicense = "-license";
        private const string cGpl = "-gpl";
        private const string cSilent = "-silent";
        private const string cHelp = "-help";

        // private members
        private TraceManager.VerboseMode verboseMode;
        private bool licence;
        private bool silent;
        private bool help;
        private string checksumCode;

        // ctor
        internal ParameterSet()
        {
            verboseMode = TraceManager.VerboseMode.None;
            licence = false;
            silent = false;
            help = false;
            checksumCode = String.Empty;
        }

        // get/set properties
        internal TraceManager.VerboseMode Verbose
        {
            get { return verboseMode; }
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

        internal string ChecksumCode
        {
            get { return checksumCode; }
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
        internal void ParseCommandLine(string[] args)
        {
            if (args == null) throw new NullReferenceException("arguments not set!");

            foreach (string arg in args)
            {
                if (arg.Equals(cVerbose, StringComparison.CurrentCultureIgnoreCase))
                {
                    // -verbose
                    this.verboseMode = TraceManager.VerboseMode.VeryVerbose;
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
                    if ((this.checksumCode == null) || String.IsNullOrEmpty(this.checksumCode)) this.checksumCode = arg;
                    else throw new ArgumentException("syntax error: multiple checksum codes specified!");
                }
            }
        }

        // validate parameter set
        internal void Validate()
        {
            // checksum code
            if (this.ChecksumCode == null || this.ChecksumCode.Length == 0) throw new ArgumentException("syntax error: no command specified!");
            if (this.ChecksumCode.Length != 2) throw new ArgumentException("syntax error: invalid checksum code (length)!");

            char firstChar = ChecksumCode[0];
            char secondChar = ChecksumCode[1];

            if (!(('0' <= firstChar && firstChar <= '9') || ('A' <= firstChar && firstChar <= 'Z'))) throw new ArgumentException("syntax error: invalid checksum code (firstChar not in 0..9 nor in A..Z)!");
            if (!('0' <= secondChar && secondChar <= '9')) throw new ArgumentException("syntax error: invalid checksum code (secondChar not in 0..9)!");
        }

    }
}
