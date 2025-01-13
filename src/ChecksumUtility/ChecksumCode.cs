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
using System.Collections.Specialized;
using System.Configuration;
using System.Reflection;
using ChecksumValidation;

namespace ChecksumValidation.ChecksumUtility
{
    public class ChecksumCode
    {
        // constants
        private const string cDefaultBankDirectory = ".";

        public static void Main(string[] args)
        {
            ParameterSet parameterSet = null;
            TraceManager traceManager = null;

            try
            {
                // display help if requested
                bool licence = false;
                bool silent = false;
                bool help = true;

                if (args.Length > 0)
                {
                    ParameterSet.LookAheadCommandLineParameters(args, out licence, out silent, out help);
                }

                if (licence)
                {
                    DisplayHelper.DisplayHeader(GetAssemblyName());
                    DisplayHelper.DisplayLicence();
                    Environment.Exit(0);
                }

                if (!silent) DisplayHelper.DisplayHeader(GetAssemblyName());

                if (help)
                {
                    DisplayHelp();
                    Environment.Exit(0);
                }

                // create parameter set
                parameterSet = new ParameterSet();

                // parse command line parameters
                parameterSet.ParseCommandLine(args);
                parameterSet.Validate();

                // set verbose level to trace manager
                traceManager = new TraceManager(parameterSet.Verbose, Console.Out);

                // do what you're supposed to do...
                ProcessInput(parameterSet, traceManager);
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.Message);
                if (ex.InnerException != null) Console.Out.WriteLine(ex.InnerException.Message);
                Console.Out.WriteLine();
            }
        }

        private static void DisplayHelp()
        {
            string assemblyName = GetAssemblyName();

            Console.Out.WriteLine("Enumerates all blz assigned to a given checksum code");
            Console.Out.WriteLine("according to the bank directory maintained and documented");
            Console.Out.WriteLine("by www.bundesbank.de.");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0} <checksum-code>", assemblyName));
            Console.Out.WriteLine("                [-silent]");
            Console.Out.WriteLine("                [-help]");
            Console.Out.WriteLine("                [-licence]");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  <checksum-code> checksum code according to www.bundesbank.de");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-licence]      displays the terms of licence for use of this software");
            Console.Out.WriteLine("  [-silent]       silent mode (default: false)");
            Console.Out.WriteLine("  [-help]         displays this text");
            Console.Out.WriteLine();
            Console.Out.WriteLine("Examples");
            Console.Out.WriteLine("--------");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0} D4", assemblyName));
            Console.Out.WriteLine();
        }

        private static string GetAssemblyName()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();
            return assemblyName.Name;
        }

        private static void ProcessInput(ParameterSet parameterSet, TraceManager traceManager)
        {
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager not set!");

            string checksumCode = parameterSet.ChecksumCode;

            string bankDirectory = ConfigurationManager.AppSettings["bank-directory"];
            if (String.IsNullOrEmpty(bankDirectory)) bankDirectory = cDefaultBankDirectory;

            StringCollection bankCodes = ValidationUtilities.FindBankCodesByChecksumCode(checksumCode, false /* get all bank codes */, bankDirectory, traceManager);

            if ((bankCodes == null) || (bankCodes.Count == 0))
            {
                Console.Out.WriteLine(String.Format("no bank code found for checksum code '{0}'", checksumCode));
            }
            else
            {
                Console.Out.WriteLine(String.Format("Bank code assigned to checksum code '{0}':", checksumCode));

                foreach (string bankCode in bankCodes)
                    Console.Out.WriteLine(String.Format("   {0}", bankCode));
            }
        }
    }
}
