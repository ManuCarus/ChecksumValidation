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
using System.Threading;

namespace ChecksumValidation
{
    public sealed class TraceManager
    {
        // verbose modes
        public enum VerboseMode { None = 0, Verbose = 1, VeryVerbose = 2, VeryVeryVerbose = 3 };

        // private members
        private VerboseMode enmMaximalVerbose = VerboseMode.None;
        private TextWriter textWriter = Console.Out;

        // ctor
        public TraceManager(VerboseMode verboseMode, TextWriter textWriter)
        {
            this.enmMaximalVerbose = verboseMode;
            this.textWriter = textWriter;
        }

        // tracer
        public void TraceLine(string line, VerboseMode verbose, bool eol)
        {
            if (String.IsNullOrEmpty(line)) return;

            if (TraceAllowed(verbose))
            {
                if (eol) textWriter.WriteLine(line); // no display of thread id if current position is at end of line
                else textWriter.WriteLine(String.Format("{0}: {1}", GetThreadName().PadRight(20, ' '), line)); ;
            }
        }

        public void TraceLine(string line, VerboseMode verbose)
        {
            TraceLine(line, verbose, false);
        }

        public void TraceLine(VerboseMode verbose, bool eol)
        {
            if (TraceAllowed(verbose))
            {
                if (eol) textWriter.WriteLine(); // no display of thread id if current position is at end of line
                else textWriter.WriteLine(GetThreadName().PadRight(20, ' '));
            }
        }

        public void TraceLine(VerboseMode verbose)
        {
            TraceLine(verbose, false);
        }

        public void Trace(string line, VerboseMode verbose, bool bol)
        {
            if (String.IsNullOrEmpty(line)) return;

            if (TraceAllowed(verbose))
            {
                if (bol) textWriter.Write(String.Format("{0}: {1}", GetThreadName().PadRight(20, ' '), line));  // display of thread id if current position is at begin of line
                else textWriter.Write(line);
            }
        }

        public void Trace(string line, VerboseMode verbose)
        {
            Trace(line, verbose, false);
        }

        private bool TraceAllowed(VerboseMode verbose)
        {
            int maximalVerboseValue = (int)enmMaximalVerbose;
            int verboseModeValue = (int)verbose;

            return (verboseModeValue <= maximalVerboseValue);
        }

        private string GetThreadName()
        {
            if (String.IsNullOrEmpty(Thread.CurrentThread.Name)) return "MainThread";
            else return Thread.CurrentThread.Name;
        }
    }
}
