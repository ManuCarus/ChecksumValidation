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

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: System.CLSCompliant(true)]

[assembly: AssemblyCompany("Manu Carus")]
[assembly: AssemblyProduct("ChecksumValidation")]
[assembly: AssemblyTitle("ChecksumValidation Unit Tests")]

[assembly: AssemblyDescription("These web services verify the validation of german bank accounts, german identity cards, " +
                               "german passports, international bank accounts (IBAN) and international credit cards. ")]

[assembly: AssemblyCopyright("Copyright (c) 2012 Manu Carus (mailto:manu.carus@ethical-hacking.de)")]

[assembly: AssemblyTrademark("This program is free software; you can redistribute it and/or modify it under the terms " +
                             "of the GNU General Public License as published by the Free Software Foundation; " +
                             "either version 3 of the License, or (at your option) any later version." +

                             "This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; " +
                             "without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. " +
                             "See the GNU General Public License for more details." +

                             "You should have received a copy of the GNU General Public License along with this program; " +
                             "if not, see <http://www.gnu.org/licenses/>")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Revision and Build Numbers 
// by using the '*' as shown below:
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: ComVisibleAttribute(false)]
