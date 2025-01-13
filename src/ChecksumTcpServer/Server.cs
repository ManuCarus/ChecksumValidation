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
using System.Reflection;
using System.Threading;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumTcpServer
{
    public sealed class Server
    {
        public static void Main(string[] args)
        {
            SecurityController securityController = null;
            ParameterSet parameterSet = null;
            TextWriter traceStream = null;
            TextWriter errorStream = null;
            TraceManager traceManager = null;
            Listener listener = null;

            try
            {
                // thread naming to distinguish output
                Thread.CurrentThread.Name = "MainThread";

                // no exchange of sensitive data without control of security
                securityController = new SecurityController();

                // display header or help?
                bool licence = false;
                bool silent = false;
                bool help = true;
                ParameterSet.LookAheadCommandLineParameters(args, out licence, out silent, out help);

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
                securityController.SetCipherKey();
                parameterSet.Validate(securityController);

                traceStream = Writer.GetTextWriter(parameterSet.Trace);
                errorStream = Writer.GetTextWriter(parameterSet.Error);

                traceManager = new TraceManager(parameterSet.Verbose, traceStream);

                listener = new Listener(securityController, parameterSet, traceManager, errorStream);
                listener.Listen();
            }
            catch (Exception ex)
            {
                if (errorStream == null) errorStream = Console.Out;

                errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss"));
                if ((parameterSet != null) && (parameterSet.Verbose == TraceManager.VerboseMode.None)) errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + ex.Message);
                else errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + ex.ToString());
                errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' '));

                if (ex.InnerException != null)
                {
                    errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' '));
                    errorStream.WriteLine(Thread.CurrentThread.Name.PadRight(20, ' ') + ex.InnerException.ToString());
                }
            }
            finally
            {
                if (errorStream != null)
                {
                    errorStream.Flush();
                    errorStream.Close();
                }

                if (traceStream != null)
                {
                    traceStream.Flush();
                    traceStream.Close();
                }
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
            Console.Out.WriteLine(String.Format("{0} [-port:<port>]", assemblyName));
            Console.Out.WriteLine("               [-trace:file]");
            Console.Out.WriteLine("               [-error:file]");
            Console.Out.WriteLine("               [-secure]");
            Console.Out.WriteLine("               [-password:pwd]");
            Console.Out.WriteLine("               [-silent]");
            Console.Out.WriteLine("               [-verbose]");
            Console.Out.WriteLine("               [-help]");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-port:<port>]  specifies the tcp port to listen to.");
            Console.Out.WriteLine("                  default: 65535.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-trace:file]   contains verbose output of the server process.");
            Console.Out.WriteLine("                  default: console.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-error:file]   error file containing detailed error messages in case.");
            Console.Out.WriteLine("                  default: console.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-secure]       indicates a secured tcp connection (e.g. ssl or ssh)");
            Console.Out.WriteLine("                  default: false.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-password:pwd] password used to secure the tcp connection");
            Console.Out.WriteLine("                  (required if -secure has not been set)");
            Console.Out.WriteLine("                  default: environment variable $CHECKSUM_PASSWORD.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-verbose]      verbose mode.");
            Console.Out.WriteLine("                  can be extended to --verbose or ---verbose.");
            Console.Out.WriteLine("                  default: none.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-licence]      displays the terms of licence for use of this software");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-silent]       silent mode.");
            Console.Out.WriteLine("                  default: false.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  [-help]         displays this text.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("Examples");
            Console.Out.WriteLine("--------");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0}", assemblyName));
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0} -port:49152", assemblyName));
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("{0} -trace:{1}.trace.txt", assemblyName, assemblyName));
            Console.Out.WriteLine(String.Format("               -error:{0}.error.txt", assemblyName));
            Console.Out.WriteLine("               -verbose");
            Console.Out.WriteLine();
        }

        private static string GetAssemblyName()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();
            return assemblyName.Name;
        }

    }
}
