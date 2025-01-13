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
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ChecksumValidation.Security
{
    public class SecurityController
    {
        // encryption defaults
        private static int cPasswordPolicyMinimumLength = 12;

        // password environment variable 
        private static string cEnvironmentVariableName = "CHECKSUM_PASSWORD";

        // security settings
        private const int cKeySize = 256; // bits
        private byte[] cSalt;
        private byte[] cIV;
        private char[] cPasswordPolicyUpperLetters; // see ctor
        private char[] cPasswordPolicyLowerLetters; // see ctor
        private char[] cPasswordPolicyDigits; // see ctor
        private char[] cPasswordPolicySpecialCharacters; // see ctor
        private char[] cAllowedCharacters; // see ctor

        // private members
        private bool secureConnection;
        private ICryptoTransform encryptor;
        private ICryptoTransform decryptor;

        // ctor
        public SecurityController()
        {
            secureConnection = false;
            encryptor = null;
            decryptor = null;

            // security settings
            cSalt = new byte[] { 150, 104, 98, 2, 205, 169, 111, 99, 57, 59, 17, 128, 238, 31, 84, 1 };
            cIV = new byte[] { 234, 39, 17, 172, 80, 156, 195, 232, 214, 216, 121, 39, 230, 166, 170, 44 };

            // password policy
            cPasswordPolicyUpperLetters = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ü', 'Ö', 'Ä' };
            cPasswordPolicyLowerLetters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ü', 'ö', 'ä' };
            cPasswordPolicyDigits = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
            cPasswordPolicySpecialCharacters = new char[] { '^', '°', '!', '"', '²', '§', '³', '$', '%', '&', '/', '(', '[', ')', ']', '}', '=', 'ß', '?', '\\', '´', '`', 
                                                            '@', '€', '+', '*', '~', '#', '\'', '<', '>', '|', 'µ', ';', ',', ':', '.', '_', '-', ' ' };

            cAllowedCharacters = new char[cPasswordPolicyUpperLetters.Length + cPasswordPolicyLowerLetters.Length + cPasswordPolicyDigits.Length + cPasswordPolicySpecialCharacters.Length];
            cPasswordPolicyUpperLetters.CopyTo(cAllowedCharacters, 0);
            cPasswordPolicyLowerLetters.CopyTo(cAllowedCharacters, cPasswordPolicyUpperLetters.Length);
            cPasswordPolicyDigits.CopyTo(cAllowedCharacters, cPasswordPolicyUpperLetters.Length + cPasswordPolicyLowerLetters.Length);
            cPasswordPolicySpecialCharacters.CopyTo(cAllowedCharacters, cPasswordPolicyUpperLetters.Length + cPasswordPolicyLowerLetters.Length + cPasswordPolicyDigits.Length);
        }

        // public properties
        public bool IsSecureConnection
        {
            get { return secureConnection; }
            set { secureConnection = value; }
        }

        public bool IsPasswordSet
        {
            get { return ((encryptor != null) && (decryptor != null)); }
        }

        public bool IsEncrypted
        {
            get { return (!IsSecureConnection); }
        }

        public ICryptoTransform Encryptor
        {
            get 
            {
                if (encryptor == null) throw new ApplicationException("key not set!");
                return encryptor; 
            }
        }

        public ICryptoTransform Decryptor
        {
            get 
            {
                if (decryptor == null) throw new ApplicationException("key not set!");
                return decryptor; 
            }
        }

        public static Encoding Encoding
        {
            get { return Encoding.Unicode; }
        }

        // if not yet set, retrieve password from environment variable
        public void SetSecuritySettings()
        {
            if (!this.IsSecureConnection && !this.IsPasswordSet)
            {
                string password = Environment.GetEnvironmentVariable(cEnvironmentVariableName, EnvironmentVariableTarget.Process);

                if (String.IsNullOrEmpty(password))
                {
                    // ok, ask for it later interactively
                }
                else
                {
                    string verificationPassword = (string)password.Clone();
                    this.SetCipherKey(ref password, ref verificationPassword);
                }
            }
        }

        // create encryptor/decryptor
        public void SetCipherKey(ref string password, ref string verifyPassword)
        {
            SymmetricAlgorithm cipher = null;
            byte[] key = null;

            try
            {
                // validation
                if (String.IsNullOrEmpty(password)) throw new ArgumentException("password must not be empty");
                if (String.IsNullOrEmpty(verifyPassword)) throw new ArgumentException("verify Password must not be empty");

                // equality of passwords
                if (!password.Equals(verifyPassword)) throw new ArgumentException("semantic error: passphrase verification failed");

                // password must be conform to password policy
                if (password.IndexOfAny(cPasswordPolicyUpperLetters) < 0) throw new ArgumentException("policy error: passphrase contains no upper case letters");
                if (password.IndexOfAny(cPasswordPolicyLowerLetters) < 0) throw new ArgumentException("policy error: passphrase contains no lower case letters");
                if (password.IndexOfAny(cPasswordPolicyDigits) < 0) throw new ArgumentException("policy error: passphrase contains no digit");
                if (password.IndexOfAny(cPasswordPolicySpecialCharacters) < 0) throw new ArgumentException("policy error: passphrase contains no special character");
                if (password.Length < cPasswordPolicyMinimumLength) throw new ArgumentException(String.Format("policy error: passphrase is too short (minimum of {0} characters)", cPasswordPolicyMinimumLength.ToString()));
                foreach (char c in password) if (Array.IndexOf(cAllowedCharacters, c) < 0) throw new ArgumentException(String.Format("policy error: passphrase contains invalid character '{0}'", c.ToString()));

                // derive key from password
                Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(password, cSalt);
                key = deriveBytes.GetBytes(cKeySize / 8);

                // aes algorithm
                cipher = new RijndaelManaged();
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.PKCS7;

                // encryption / decryption
                this.encryptor = cipher.CreateEncryptor(key, cIV);
                this.decryptor = cipher.CreateDecryptor(key, cIV);
            }
            finally
            {
                // delete passwords, key and cipher from memory
                password = null;
                verifyPassword = null;
                key = null;
                cipher = null;

                GC.Collect();
            }
        }

        public void SetCipherKey()
        {
            if (!this.IsSecureConnection && !this.IsPasswordSet)
            {
                string password = String.Empty;
                while (String.IsNullOrEmpty(password)) password = ReadPasswordFromStdin("Please enter a passphrase to secure the connection: ");

                string verifyPassword = String.Empty;
                while (String.IsNullOrEmpty(verifyPassword)) verifyPassword = ReadPasswordFromStdin("Verify passphrase: ");

                this.SetCipherKey(ref password, ref verifyPassword);
            }
        }

        // enter password interactively
        private string ReadPasswordFromStdin(string prompt)
        {
            string password = String.Empty;

            while (String.IsNullOrEmpty(password))
            {
                if (!String.IsNullOrEmpty(prompt)) Console.Out.Write(prompt);

                StringBuilder userInput = new StringBuilder();
                ConsoleKeyInfo key;

                do
                {
                    key = Console.ReadKey(true);
                    if (key.Key != ConsoleKey.Enter) userInput.Append(key.KeyChar);
                }
                while (key.Key != ConsoleKey.Enter);

                password = userInput.ToString();
                Console.Out.WriteLine();
            }

            return password;
        }

        // security validation
        public void Validate()
        {
            // password
            if (!this.IsSecureConnection && !this.IsPasswordSet) throw new ArgumentException("security error: no passphrase set for insecure connection");

            if (this.IsSecureConnection)
            {
                // ok, secure connection
            }
            else if (!this.IsPasswordSet)
            {
                throw new ArgumentException("syntax error: no passphrase set");
            }
        }

        // send data over a tcp connection (either secured or encrypted)
        public void Send(TcpClient tcpClient, string data)
        {
            // validation
            if (tcpClient == null) throw new ArgumentException("tcp client not initialized!");
            if (String.IsNullOrEmpty(data)) throw new ArgumentException("no data to transmit");

            // transmittance
            if (this.IsEncrypted)
            {
                MemoryStream memoryStream = null;
                CryptoStream cryptoStream = null;

                try
                {
                    // translate the data into a byte array
                    byte[] binaryData = Encoding.GetBytes(data);

                    // encrypt data into memory (to know how many bytes to send)
                    memoryStream = new MemoryStream();
                    cryptoStream = new CryptoStream(memoryStream, this.Encryptor, CryptoStreamMode.Write);

                    cryptoStream.Write(binaryData, 0, binaryData.Length);
                    cryptoStream.FlushFinalBlock();

                    // length of encrypted data
                    byte[] encryptedData = memoryStream.GetBuffer();
                    Int32 length = (Int32)memoryStream.Length;

                    // send length of data to transmit so that receiver knows how many bytes to read from the network stream
                    byte[] header = BitConverter.GetBytes(length);
                    if (header.Length != 4) throw new ApplicationException(String.Format("internal error: length of header is {0} bytes!", header.Length.ToString()));

                    Write(tcpClient, header, 4);

                    // send encrypted data over the channel 
                    Write(tcpClient, encryptedData, length);
                }
                finally
                {
                    if (cryptoStream != null) cryptoStream.Close();
                    if (memoryStream != null) memoryStream.Close();
                }
            }
            else // this.IsSecureConnection = true
            {
                // translate the data into a byte array
                byte[] binaryData = Encoding.GetBytes(data);
                Int32 length = binaryData.Length; // 32bit unsigned integer (4 bytes)

                // send length of data to transmit so that receiver knows how many bytes to read from the network stream
                byte[] header = BitConverter.GetBytes(length);
                if (header.Length != 4) throw new ApplicationException(String.Format("internal error: length of header is {0} bytes!", header.Length.ToString()));

                Write(tcpClient, header, 4);

                // send the data in cleartext over a secured channel 
                Write(tcpClient, binaryData, length);
            }
        }

        // receive data from a tcp connection (either secured or encrypted)
        public string Receive(TcpClient tcpClient)
        {
            // validation
            if (tcpClient == null) throw new ArgumentException("tcp client not initialized!");

            // listening
            if (this.IsEncrypted)
            {
                MemoryStream memoryStream = null;
                CryptoStream cryptoStream = null;

                try
                {
                    // crypto stream
                    memoryStream = new MemoryStream();
                    cryptoStream = new CryptoStream(memoryStream, this.Decryptor, CryptoStreamMode.Write);

                    // read header (length of transmitted data)
                    byte[] buffer = new byte[256];

                    int bytesRead = Read(tcpClient, ref buffer, 4);
                    Int32 dataLength = BitConverter.ToInt32(buffer, 0);

                    // read encrypted data and decrypt into memory
                    int offset = 0;
                    while (dataLength > 0)
                    {
                        bytesRead = Read(tcpClient, ref buffer, Math.Min(buffer.Length, dataLength));
                        cryptoStream.Write(buffer, 0, bytesRead);
                        offset += bytesRead;
                        dataLength -= bytesRead;
                    }

                    cryptoStream.FlushFinalBlock();

                    // retrieve decrypted data from memory
                    memoryStream.Position = 0;
                    byte[] decryptedData = memoryStream.GetBuffer();
                    Int32 decryptedDataLength = (Int32)memoryStream.Length;

                    string data = Encoding.GetString(decryptedData, 0, decryptedDataLength);
                    return data;
                }
                finally
                {
                    if (cryptoStream != null) cryptoStream.Close();
                    if (memoryStream != null) memoryStream.Close();
                }
            }
            else // this.IsSecureConnection = true
            {
                // read header (length of transmitted data)
                byte[] buffer = new byte[256];

                int bytesRead = Read(tcpClient, ref buffer, 4);
                Int32 dataLength = BitConverter.ToInt32(buffer, 0);

                // read data
                StringBuilder data = new StringBuilder();

                while (dataLength > 0)
                {
                    bytesRead = Read(tcpClient, ref buffer, Math.Min(buffer.Length, dataLength));
                    dataLength -= bytesRead;

                    string dataChunk = Encoding.GetString(buffer, 0, bytesRead);
                    data.Append(dataChunk);
                }

                return data.ToString();
            }
        }

        private NetworkStream GetClientStream(TcpClient tcpClient)
        {
            NetworkStream clientStream;

            try { clientStream = tcpClient.GetStream(); }
            catch (IOException) { tcpClient.Close(); throw; } // [System.IO.IOException] = {"Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."}
            catch (ObjectDisposedException) { tcpClient.Close(); throw; } // connection was forcibly closed by the remote host.

            return clientStream;
        }

        private int Read(TcpClient tcpClient, ref byte[] buffer, int count)
        {
            // client stream
            NetworkStream clientStream = GetClientStream(tcpClient);

            // read count bytes (eventually terminate communication)
            int bytesRead;

            try { bytesRead = clientStream.Read(buffer, 0, count); }
            catch (IOException) { tcpClient.Close(); throw; } // [System.IO.IOException] = {"Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."}
            catch (ObjectDisposedException) { tcpClient.Close(); throw; } // [System.IO.IOException] = {"Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."}

            return bytesRead;
        }

        private void Write(TcpClient tcpClient, byte[] buffer, int count)
        {
            // client stream
            NetworkStream clientStream = GetClientStream(tcpClient);

            // write count bytes (eventually terminate communication)
            try { clientStream.Write(buffer, 0, count); clientStream.Flush(); }
            catch (IOException) { tcpClient.Close(); throw; } // [System.IO.IOException] = {"Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."}
            catch (ObjectDisposedException) { tcpClient.Close(); throw; } // [System.IO.IOException] = {"Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."}
        }

    }
}
