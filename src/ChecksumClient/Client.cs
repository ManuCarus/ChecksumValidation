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
using System.Reflection;
using System.Text;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumClient
{
    public sealed class Client
    {
        public static void Main(string[] args)
        {
            SecurityController securityController = null;
            ParameterSet parameterSet = null;
            TraceManager traceManager = null;

            try
            {
                // no exchange of sensitive data without control of security
                securityController = new SecurityController();

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
                parameterSet.ParseCommandLine(args, securityController);
                if ((parameterSet.Communication == ParameterSet.CommunicationMode.Tcp) && (parameterSet.UserInterface == ParameterSet.UserInterfaceMode.Console) && parameterSet.RequiresSecureConnection) securityController.SetCipherKey();
                parameterSet.Validate(securityController);

                // set verbose level to trace manager
                traceManager = new TraceManager(parameterSet.Verbose, Console.Out);

                // do what you're supposed to do...
                ProcessInput(securityController, parameterSet, traceManager);
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

            Console.Out.WriteLine("Validates german bank accounts by computing a checksum according to the");
            Console.Out.WriteLine("algorithms maintained and documented by www.bundesbank.de.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("Also validates german identity cards, german passports,");
            Console.Out.WriteLine("international bank accounts (IBAN) and credit cards.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("The following interfaces to the server are available:");
            Console.Out.WriteLine();
            Console.Out.WriteLine("   - Tcp Listener");
            Console.Out.WriteLine("   - SOAP Web Service");
            Console.Out.WriteLine("   - In-Proc");
            Console.Out.WriteLine("   - COM");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0} command", assemblyName));
            Console.Out.WriteLine("               [-inproc|-tcp|-soap|-com]");
            Console.Out.WriteLine("               [-console|-gui]");
            Console.Out.WriteLine("               [-secure]");
            Console.Out.WriteLine("               [-password:pwd]");
            Console.Out.WriteLine("               [-verbose]");
            Console.Out.WriteLine("               [-silent]");
            Console.Out.WriteLine("               [-help]");
            Console.Out.WriteLine("               [-licence]");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  command         command to be sent to the checksum server");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  -inproc         client integrates a local checksum server (default)");
            Console.Out.WriteLine("  -tcp            client connects via tcp to the checksum server");
            Console.Out.WriteLine("  -soap           client connects via web service to the checksum server");
            Console.Out.WriteLine("  -com            client connects via COM to the checksum server");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  -console        command line tool (default)");
            Console.Out.WriteLine("  -gui            graphical user interface");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-secure]       indicates a secured tcp connection (e.g. ssl or ssh)");
            Console.Out.WriteLine("                  default: false.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-password:pwd] password used to secure the tcp connection");
            Console.Out.WriteLine("                  (useful only in combination with -tcp)");
            Console.Out.WriteLine("                  (required if -secure has not been set)");
            Console.Out.WriteLine("                  default: console input if -console is set.");
            Console.Out.WriteLine("                           user input if -gui is set.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-verbose]      verbose mode (can be extended to --verbose or ---verbose)");
            Console.Out.WriteLine("                  (useful only in combination with -inproc)");
            Console.Out.WriteLine("  [-licence]      displays the terms of licence for use of this software");
            Console.Out.WriteLine("  [-silent]       silent mode (default: false)");
            Console.Out.WriteLine("  [-help]         displays this text");
            Console.Out.WriteLine();
            Console.Out.WriteLine("Examples");
            Console.Out.WriteLine("--------");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0} -inproc account:1234567897/37050299", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -soap iban:DE60700517550000007229", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -com to-iban:1234567890/37050299", assemblyName));
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0} -tcp cache", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp account:1234567897/37050299", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp format-blz:37050299", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp iban:DE60700517550000007229", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp to-iban:1234567890/37050299", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp format-iban:DE60700517550000007229", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp \"identity:2406055684D<<6810203<0705109<<<<<<6\"", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp \"passport:2406055684D<<6810203M0705109<<<<<<<<<<<<<<<6\"", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp credit-card:4509472140549006", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp get-credit-card-type:4509472140549006", assemblyName));
            Console.Out.WriteLine(String.Format("{0} -tcp stop", assemblyName));
            Console.Out.WriteLine();
        }

        private static string GetAssemblyName()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();
            return assemblyName.Name;
        }

        private static void ProcessInput(SecurityController securityController, ParameterSet parameterSet, TraceManager traceManager)
        {
            if (securityController == null) throw new NullReferenceException("security controller not set!");
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager not set!");

            if (parameterSet.UserInterface == ParameterSet.UserInterfaceMode.Console)
            {
                IProxy proxy = CommandHandler.CreateProxy(securityController, parameterSet.Communication, parameterSet, traceManager);
                string result = CommandHandler.HandleCommandThroughCommunicationChannel(proxy, parameterSet.Command);
                traceManager.TraceLine(result, TraceManager.VerboseMode.None);
            }
            else if (parameterSet.UserInterface == ParameterSet.UserInterfaceMode.Gui)
            {
                MainForm form = new MainForm(securityController, parameterSet, traceManager);
                form.ShowDialog();             
            }
            else
            {
                throw new Exception("invalid user interface mode!");
            }
        }

    }
}
