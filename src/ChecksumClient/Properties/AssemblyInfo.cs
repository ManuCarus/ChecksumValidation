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

// General Information about an assembly is controlled through the following 
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.

[assembly: AssemblyCompany("Manu Carus")]
[assembly: AssemblyProduct("ChecksumValidation")]
[assembly: AssemblyTitle("ChecksumValidation Client")]

[assembly: AssemblyDescription("This Windows Client GUI Application offers diverse ways to validate german bank accounts, " +
                               "german identity cards, german passports, international bank accounts (IBAN) and " +
                               "international credit cards: In-Process Invocation, TCP, SOAP, COM.")]

[assembly: AssemblyCopyright("Copyright (c) 2012 Manu Carus (mailto:manu.carus@ethical-hacking.de)")]

[assembly: AssemblyTrademark("This program is free software; you can redistribute it and/or modify it under the terms " +
                             "of the GNU General Public License as published by the Free Software Foundation; " +
                             "either version 3 of the License, or (at your option) any later version." +

                             "This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; " +
                             "without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. " +
                             "See the GNU General Public License for more details." +

                             "You should have received a copy of the GNU General Public License along with this program; " +
                             "if not, see <http://www.gnu.org/licenses/>")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("82e5dc4c-8fdf-4c81-b47b-03bb8c267a62")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
