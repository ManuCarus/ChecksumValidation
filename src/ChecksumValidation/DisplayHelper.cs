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

namespace ChecksumValidation
{
    public class DisplayHelper
    {
        private const string cFilenameGpl = "gpl.txt";

        public static void DisplayHeader(string assemblyName)
        {
            if (assemblyName == null) throw new ArgumentNullException("assemblyName");

            Console.Out.WriteLine("ChecksumValidation Copyright (C) 2012 Manu Carus (manu.carus@ethical-hacking.de)");
            Console.Out.WriteLine("This program comes with ABSOLUTELY NO WARRANTY; for details type ");
            Console.Out.WriteLine(String.Format("'{0} -licence'.", assemblyName));
            Console.Out.WriteLine("This is free software, and you are welcome to redistribute it under certain ");
            Console.Out.WriteLine("conditions; refer to GNU GPLv3 <http://www.gnu.org/licenses/> for details.");
            Console.Out.WriteLine();
        }

        public static void DisplayLicence()
        {
            if (File.Exists(cFilenameGpl))
            {
                TextReader textReader = null;

                try
                {
                    textReader = new StreamReader(cFilenameGpl);
                    string licence = textReader.ReadToEnd();
                    Console.Out.WriteLine(licence);
                }
                catch (Exception ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                finally
                {
                    if (textReader != null) textReader.Close();
                }
            }
            else
            {
                Console.Out.WriteLine("Please refer to <http://www.gnu.org/licenses/gpl-3.0.txt> for licence terms.");
            }
        }

    }
}
