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
using System.IO;
using System.Text;

namespace ChecksumValidation.BankAccountValidation
{
    internal sealed class BankFactory
    {
        // private members
        private static int cCountColumns = 168;
        private static int cCapacity = 5000;

        // load blzs from file into hashtable
        internal static Hashtable GetBanks(string bankDirectoryFile, TraceManager traceManager)
        {
            if (String.IsNullOrEmpty(bankDirectoryFile)) throw new ChecksumException("argument:1603", "bank directory file name must not be empty");

            try
            {
                Hashtable bankDirectory = new Hashtable(cCapacity);

                int linePos = 0;
                string line = String.Empty;

                using (StreamReader streamReader = new StreamReader(bankDirectoryFile, Encoding.Default))
                {
                    while ((line = streamReader.ReadLine()) != null)
                    {
                        linePos++;

                        if ((line.Length == 1) && (Char.GetNumericValue(line[0]) == -1)) break; // end-of-file

                        if (line.Length != cCountColumns) throw new ChecksumException("argument:1604", String.Format("line {0} contains {1} columns (must be {2} characters):\n{3}", linePos.ToString(), line.Length.ToString(), cCountColumns.ToString(), line));

                        string blz = line.Substring(0, 8).Trim();
                        string leadingInstitute = line.Substring(8, 1).Trim();
                        string institute = line.Substring(9, 58).Trim();
                        string zipcode = line.Substring(67, 5).Trim();
                        string city = line.Substring(72, 35).Trim();
                        string instituteShortName = line.Substring(107, 27).Trim();
                        string pan = line.Substring(134, 5).Trim();
                        string bic = line.Substring(139, 11).Trim();
                        string checksumCode = line.Substring(150, 2).Trim();
                        string id = line.Substring(152, 6).Trim();
                        string changeFlag = line.Substring(158, 1).Trim();
                        string toBeDeleted = line.Substring(159, 1).Trim();
                        string successorBlz = line.Substring(160, 8).Trim();

                        if (!blz.Equals("00000000") && leadingInstitute.Equals("1"))
                        {
                            Bank bank = new Bank(blz, checksumCode);
                            bankDirectory.Add(blz, bank);

                            if (linePos % 100 == 0) traceManager.Trace(".", TraceManager.VerboseMode.VeryVerbose, false);
                        }
                    }
                }

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose, true);
                traceManager.TraceLine(String.Format("loaded {0} items...", bankDirectory.Count.ToString()), TraceManager.VerboseMode.VeryVerbose);

                return bankDirectory;
            }
            catch(BankException ex)
            {
                throw ex;
            }
            catch (Exception ex)
            {
                throw new ChecksumException("argument:1605", String.Format("unexpected error occurred in BankFactory.GetBanks (bankDirectoryFile = '{0}')", bankDirectoryFile), ex);
            }
        }
    }
}
