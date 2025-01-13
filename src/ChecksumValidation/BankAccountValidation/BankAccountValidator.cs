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
using System.Configuration;
using System.IO;
using System.Text;

namespace ChecksumValidation.BankAccountValidation
{
    public sealed class BankAccountValidator
    {
        // bank directory: filename format
        private const string cBankDirectoryFile = "blz_????????.txt"; // standard format: blz_20090309.txt

        // maximum amount of allowed digits
        private static byte cMaxDigitsAccount = 10;

        // weighting
        private static byte[] cWeighting_1_2 = { 1, 2 };
        private static byte[] cWeighting_2_1 = { 2, 1 };
        private static byte[] cWeighting_3_1 = { 3, 1 };
        private static byte[] cWeighting_1_2_3 = { 1, 2, 3 };
        private static byte[] cWeighting_1_3_2 = { 1, 3, 2 };
        private static byte[] cWeighting_3_1_7 = { 3, 1, 7 };
        private static byte[] cWeighting_3_7_1 = { 3, 7, 1 };
        private static byte[] cWeighting_7_3_1 = { 7, 3, 1 };
        private static byte[] cWeighting_2_3_4_5 = { 2, 3, 4, 5 };
        private static byte[] cWeighting_2_4_8_5 = { 2, 4, 8, 5 };
        private static byte[] cWeighting_3_9_7_1 = { 3, 9, 7, 1 };
        private static byte[] cWeighting_1_2_3_4_5 = { 1, 2, 3, 4, 5 };
        private static byte[] cWeighting_2_3_4_5_6 = { 2, 3, 4, 5, 6 };
        private static byte[] cWeighting_2_4_8_5_A = { 2, 4, 8, 5, 10 };
        private static byte[] cWeighting_5_4_3_4_5 = { 5, 4, 3, 4, 5 };
        private static byte[] cWeighting_1_2_3_4_5_6 = { 1, 2, 3, 4, 5, 6 };
        private static byte[] cWeighting_2_3_4_5_6_7 = { 2, 3, 4, 5, 6, 7 };
        private static byte[] cWeighting_2_4_8_5_A_9 = { 2, 4, 8, 5, 10, 9 };
        private static byte[] cWeighting_6_5_4_3_2_1 = { 6, 5, 4, 3, 2, 1 };
        private static byte[] cWeighting_7_6_5_4_3_2 = { 7, 6, 5, 4, 3, 2 };
        private static byte[] cWeighting_9_A_5_8_4_2 = { 9, 10, 5, 8, 4, 2 };
        private static byte[] cWeighting_2_3_4_5_6_7_2 = { 2, 3, 4, 5, 6, 7, 2 };
        private static byte[] cWeighting_2_3_4_5_6_7_8 = { 2, 3, 4, 5, 6, 7, 8 };
        private static byte[] cWeighting_2_4_8_5_A_9_7 = { 2, 4, 8, 5, 10, 9, 7 };
        private static byte[] cWeighting_2_3_4_5_6_0_0_7 = { 2, 3, 4, 5, 6, 0, 0, 7 };
        private static byte[] cWeighting_2_3_4_5_6_7_8_9 = { 2, 3, 4, 5, 6, 7, 8, 9 };
        private static byte[] cWeighting_1_2_3_4_5_6_7_8_9 = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        private static byte[] cWeighting_2_0_0_0_0_1_2_1_2 = { 2, 0, 0, 0, 0, 1, 2, 1, 2 };
        private static byte[] cWeighting_2_1_2_1_2_1_2_0_0 = { 2, 1, 2, 1, 2, 1, 2, 0, 0 };
        private static byte[] cWeighting_2_3_4_5_6_7_0_0_0 = { 2, 3, 4, 5, 6, 7, 0, 0, 0 };
        private static byte[] cWeighting_2_3_4_5_6_7_2_3_4 = { 2, 3, 4, 5, 6, 7, 2, 3, 4 };
        private static byte[] cWeighting_2_3_4_5_6_7_8_0_0 = { 2, 3, 4, 5, 6, 7, 8, 0, 0 };
        private static byte[] cWeighting_2_3_4_5_6_7_8_7_8 = { 2, 3, 4, 5, 6, 7, 8, 7, 8 };
        private static byte[] cWeighting_2_3_4_5_6_7_8_9_1 = { 2, 3, 4, 5, 6, 7, 8, 9, 1 };
        private static byte[] cWeighting_2_3_4_5_6_7_8_9_2 = { 2, 3, 4, 5, 6, 7, 8, 9, 2 };
        private static byte[] cWeighting_2_3_4_5_6_7_8_9_3 = { 2, 3, 4, 5, 6, 7, 8, 9, 3 };
        private static byte[] cWeighting_2_3_4_5_6_7_8_9_A = { 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        private static byte[] cWeighting_2_4_8_5_A_0_0_0_0 = { 2, 4, 8, 5, 10, 0, 0, 0, 0 };
        private static byte[] cWeighting_2_4_8_5_A_9_7_3_6 = { 2, 4, 8, 5, 10, 9, 7, 3, 6 };
        private static byte[] cWeighting_9_8_7_6_5_4_3_2_1 = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
        private static byte[] cWeighting_2_3_4_0_5_6_7_8_9_A = { 2, 3, 4, 0, 5, 6, 7, 8, 9, 10 };
        private static byte[] cWeighting_2_4_8_5_A_9_7_3_6_1_2_4 = { 2, 4, 8, 5, 10, 9, 7, 3, 6, 1, 2, 4 };

        // transformation table
        private static byte[][] cTransformationMeh = { new byte[] { 0,1,5,9,3,7,4,8,2,6 },
                                                       new byte[] { 0,1,7,6,9,8,3,2,5,4 },
                                                       new byte[] { 0,1,8,4,6,2,9,5,7,3 },
                                                       new byte[] { 0,1,2,3,4,5,6,7,8,9 }
                                                     };

        // checksum mappings
        private static Hashtable cChecksumMapping_7_0;
        private static Hashtable cChecksumMapping_9_0;
        private static Hashtable cChecksumMapping_10_0;
        private static Hashtable cChecksumMapping_11_0;
        private static Hashtable cChecksumMapping_10_0_11_0;
        private static Hashtable cChecksumMapping_10_9_11_0;

        // commonly used algorithms
        private static string cCommonAlgorithms00 = "00_08_13_21_27_30_41_45_57_59_60_65_67_68_72_73_74_75_78_79_80_86_94_A1_A8_B4_C6_D1_D4_D6_D8";
        private static string cCommonAlgorithms01 = "01_03_05_18_92_98_B5_D6";
        private static string cCommonAlgorithms02 = "02_04_07_14_58_85_B4_D6";
        private static string cCommonAlgorithms06 = "06_10_11_15_16_19_20_23_26_28_32_33_34_36_37_38_39_40_42_44_46_47_48_50_51A_51B_51C_55_64_70_73_83_85_88_89_90_91_93_95_A4_D5";

        // trim array of characters
        private static char[] cUnderscore = { '_' };
        private static char[] c0 = { '0' };
        private static char[] c123456789 = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };

        // no validation algorithm
        private static string cNoValidationAlgorithm = "09";

        // private members
        private TraceManager traceManager;
        private ValidationUtilities validationUtilities;
        private Hashtable bankDirectory;
        private string baseDir;
        private Object thisLock;

        // public properties
        public Hashtable Banks
        {
            get 
            {
                return bankDirectory;
            }
        }

        // ctors
        public BankAccountValidator(TraceManager traceManager, string baseDir)
        {
            // lock for multithreaded access to this.bankDirectory
            thisLock = new Object();

            this.traceManager = traceManager;
            this.validationUtilities = new ValidationUtilities(traceManager);
            this.bankDirectory = null;
            this.baseDir = baseDir;

            // initialize checksum mapping tables
            cChecksumMapping_7_0 = new Hashtable(1);
            cChecksumMapping_7_0.Add((byte)7, (byte)0);

            cChecksumMapping_9_0 = new Hashtable(1);
            cChecksumMapping_9_0.Add((byte)9, (byte)0);

            cChecksumMapping_10_0 = new Hashtable(1);
            cChecksumMapping_10_0.Add((byte)10, (byte)0);

            cChecksumMapping_11_0 = new Hashtable(1);
            cChecksumMapping_11_0.Add((byte)11, (byte)0);

            cChecksumMapping_10_0_11_0 = new Hashtable(2);
            cChecksumMapping_10_0_11_0.Add((byte)10, (byte)0);
            cChecksumMapping_10_0_11_0.Add((byte)11, (byte)0);

            cChecksumMapping_10_9_11_0 = new Hashtable(2);
            cChecksumMapping_10_9_11_0.Add((byte)10, (byte)9);
            cChecksumMapping_10_9_11_0.Add((byte)11, (byte)0);
        }

        // load bank directory into memory
        public void Load()
        {
            lock (thisLock)
            {
                // don't load twice
                if ((bankDirectory != null) && (bankDirectory.Count > 0)) return;

                // look for current bank directory file
                string[] files = Directory.GetFiles(this.baseDir, cBankDirectoryFile, SearchOption.TopDirectoryOnly);
                if ((files == null) || (files.Length == 0)) throw new ChecksumException("configuration:4001", "could not find blz directory", new ConfigurationErrorsException(String.Format("configuration error: couldn't find bank directory with pattern {0} in directory {1}", cBankDirectoryFile, this.baseDir)));
                Array.Sort(files);

                // look for a file <= blz_<today>.txt (where <today> is of format YYYYMMDD)
                string todayYYYYMMDD = DateTime.Now.ToString("yyyyMMdd");
                string todayBankDirectory = this.baseDir + String.Format("blz_{0}.txt", todayYYYYMMDD);
                int pos = ~Array.BinarySearch(files, todayBankDirectory);
                if (pos == 0) throw new ChecksumException("configuration:4002", "could not find blz files", new ConfigurationErrorsException(String.Format("configuration error: couldn't find bank directory with pattern {0} in directory {1} which is valid for {2}", cBankDirectoryFile, this.baseDir, todayYYYYMMDD)));

                string currentBankDirectoryFile = files[pos-1];
                this.traceManager.TraceLine(String.Format("loading banks from directory file '{0}'...", currentBankDirectoryFile), TraceManager.VerboseMode.VeryVerbose);

                this.bankDirectory = BankFactory.GetBanks(currentBankDirectoryFile, traceManager);
            }
        }

        // validate blz and account against computed checksum
        public void Validate(string blz, string account)
        {
            if (String.IsNullOrEmpty(blz)) throw new NullReferenceException("blz must not be empty");
            if (String.IsNullOrEmpty(account)) throw new NullReferenceException("account must not be empty");

            RegexChecker.ValidateBlz(blz);
            RegexChecker.ValidateAccount(account);

            // load bank directory
            if ((bankDirectory == null) || (bankDirectory.Count == 0)) Load();

            // retrieve algorithm id from blz
            string checksum;
            bool validate;

            GetBlzAlgorithmNumber(blz, out checksum, out validate);

            string account10Digits = account.PadLeft(cMaxDigitsAccount, '0');

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("Algorithm:      {0}", checksum), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("Blz:            {0}", blz), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("Account:        {0}", account10Digits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            if (!validate)
            {
                // do not validate
                traceManager.TraceLine(String.Format("validate:       {0} (blz doesn't need not to be validated)", validate.ToString()), TraceManager.VerboseMode.VeryVerbose);
                return;
            }

            // validate
            switch (checksum)
            {
                case "00": ValidateAccountAlgorithm00(blz, account10Digits); break;
                case "01": ValidateAccountAlgorithm01(blz, account10Digits); break;
                case "02": ValidateAccountAlgorithm02(blz, account10Digits); break;
                case "03": ValidateAccountAlgorithm03(blz, account10Digits); break;
                case "04": ValidateAccountAlgorithm04(blz, account10Digits); break;
                case "05": ValidateAccountAlgorithm05(blz, account10Digits); break;
                case "06": ValidateAccountAlgorithm06(blz, account10Digits); break;
                case "07": ValidateAccountAlgorithm07(blz, account10Digits); break;
                case "08": ValidateAccountAlgorithm08(blz, account10Digits); break;
                case "09": ValidateAccountAlgorithm09(blz, account10Digits); break;
                case "10": ValidateAccountAlgorithm10(blz, account10Digits); break;
                case "11": ValidateAccountAlgorithm11(blz, account10Digits); break;
                case "13": ValidateAccountAlgorithm13(blz, account10Digits); break;
                case "14": ValidateAccountAlgorithm14(blz, account10Digits); break;
                case "15": ValidateAccountAlgorithm15(blz, account10Digits); break;
                case "16": ValidateAccountAlgorithm16(blz, account10Digits); break;
                case "17": ValidateAccountAlgorithm17(blz, account10Digits); break;
                case "18": ValidateAccountAlgorithm18(blz, account10Digits); break;
                case "19": ValidateAccountAlgorithm19(blz, account10Digits); break;
                case "20": ValidateAccountAlgorithm20(blz, account10Digits); break;
                case "21": ValidateAccountAlgorithm21(blz, account10Digits); break;
                case "22": ValidateAccountAlgorithm22(blz, account10Digits); break;
                case "23": ValidateAccountAlgorithm23(blz, account10Digits); break;
                case "24": ValidateAccountAlgorithm24(blz, account10Digits); break;
                case "25": ValidateAccountAlgorithm25(blz, account10Digits); break;
                case "26": ValidateAccountAlgorithm26(blz, account10Digits); break;
                case "27": ValidateAccountAlgorithm27(blz, account10Digits); break;
                case "28": ValidateAccountAlgorithm28(blz, account10Digits); break;
                case "29": ValidateAccountAlgorithm29(blz, account10Digits); break;
                case "30": ValidateAccountAlgorithm30(blz, account10Digits); break;
                case "31": ValidateAccountAlgorithm31(blz, account10Digits); break;
                case "32": ValidateAccountAlgorithm32(blz, account10Digits); break;
                case "33": ValidateAccountAlgorithm33(blz, account10Digits); break;
                case "34": ValidateAccountAlgorithm34(blz, account10Digits); break;
                case "35": ValidateAccountAlgorithm35(blz, account10Digits); break;
                case "36": ValidateAccountAlgorithm36(blz, account10Digits); break;
                case "37": ValidateAccountAlgorithm37(blz, account10Digits); break;
                case "38": ValidateAccountAlgorithm38(blz, account10Digits); break;
                case "39": ValidateAccountAlgorithm39(blz, account10Digits); break;
                case "40": ValidateAccountAlgorithm40(blz, account10Digits); break;
                case "41": ValidateAccountAlgorithm41(blz, account10Digits); break;
                case "42": ValidateAccountAlgorithm42(blz, account10Digits); break;
                case "43": ValidateAccountAlgorithm43(blz, account10Digits); break;
                case "44": ValidateAccountAlgorithm44(blz, account10Digits); break;
                case "45": ValidateAccountAlgorithm45(blz, account10Digits); break;
                case "46": ValidateAccountAlgorithm46(blz, account10Digits); break;
                case "47": ValidateAccountAlgorithm47(blz, account10Digits); break;
                case "48": ValidateAccountAlgorithm48(blz, account10Digits); break;
                case "49": ValidateAccountAlgorithm49(blz, account10Digits); break;
                case "50": ValidateAccountAlgorithm50(blz, account10Digits); break;
                case "51": ValidateAccountAlgorithm51(blz, account10Digits); break;
                case "52": ValidateAccountAlgorithm52(blz, account10Digits); break;
                case "53": ValidateAccountAlgorithm53(blz, account10Digits); break;
                case "54": ValidateAccountAlgorithm54(blz, account10Digits); break;
                case "55": ValidateAccountAlgorithm55(blz, account10Digits); break;
                case "56": ValidateAccountAlgorithm56(blz, account10Digits); break;
                case "57": ValidateAccountAlgorithm57(blz, account10Digits); break;
                case "58": ValidateAccountAlgorithm58(blz, account10Digits); break;
                case "59": ValidateAccountAlgorithm59(blz, account10Digits); break;
                case "60": ValidateAccountAlgorithm60(blz, account10Digits); break;
                case "61": ValidateAccountAlgorithm61(blz, account10Digits); break;
                case "62": ValidateAccountAlgorithm62(blz, account10Digits); break;
                case "63": ValidateAccountAlgorithm63(blz, account10Digits); break;
                case "64": ValidateAccountAlgorithm64(blz, account10Digits); break;
                case "65": ValidateAccountAlgorithm65(blz, account10Digits); break;
                case "66": ValidateAccountAlgorithm66(blz, account10Digits); break;
                case "67": ValidateAccountAlgorithm67(blz, account10Digits); break;
                case "68": ValidateAccountAlgorithm68(blz, account10Digits); break;
                case "69": ValidateAccountAlgorithm69(blz, account10Digits); break;
                case "70": ValidateAccountAlgorithm70(blz, account10Digits); break;
                case "71": ValidateAccountAlgorithm71(blz, account10Digits); break;
                case "72": ValidateAccountAlgorithm72(blz, account10Digits); break;
                case "73": ValidateAccountAlgorithm73(blz, account10Digits); break;
                case "74": ValidateAccountAlgorithm74(blz, account10Digits); break;
                case "75": ValidateAccountAlgorithm75(blz, account10Digits); break;
                case "76": ValidateAccountAlgorithm76(blz, account10Digits); break;
                case "77": ValidateAccountAlgorithm77(blz, account10Digits); break;
                case "78": ValidateAccountAlgorithm78(blz, account10Digits); break;
                case "79": ValidateAccountAlgorithm79(blz, account10Digits); break;
                case "80": ValidateAccountAlgorithm80(blz, account10Digits); break;
                case "81": ValidateAccountAlgorithm81(blz, account10Digits); break;
                case "82": ValidateAccountAlgorithm82(blz, account10Digits); break;
                case "83": ValidateAccountAlgorithm83(blz, account10Digits); break;
                case "84": ValidateAccountAlgorithm84(blz, account10Digits); break;
                case "85": ValidateAccountAlgorithm85(blz, account10Digits); break;
                case "86": ValidateAccountAlgorithm86(blz, account10Digits); break;
                case "87": ValidateAccountAlgorithm87(blz, account10Digits); break;
                case "88": ValidateAccountAlgorithm88(blz, account10Digits); break;
                case "89": ValidateAccountAlgorithm89(blz, account10Digits); break;
                case "90": ValidateAccountAlgorithm90(blz, account10Digits); break;
                case "91": ValidateAccountAlgorithm91(blz, account10Digits); break;
                case "92": ValidateAccountAlgorithm92(blz, account10Digits); break;
                case "93": ValidateAccountAlgorithm93(blz, account10Digits); break;
                case "94": ValidateAccountAlgorithm94(blz, account10Digits); break;
                case "95": ValidateAccountAlgorithm95(blz, account10Digits); break;
                case "96": ValidateAccountAlgorithm96(blz, account10Digits); break;
                case "97": ValidateAccountAlgorithm97(blz, account10Digits); break;
                case "98": ValidateAccountAlgorithm98(blz, account10Digits); break;
                case "99": ValidateAccountAlgorithm99(blz, account10Digits); break;
                case "A0": ValidateAccountAlgorithmA0(blz, account10Digits); break;
                case "A1": ValidateAccountAlgorithmA1(blz, account10Digits); break;
                case "A2": ValidateAccountAlgorithmA2(blz, account10Digits); break;
                case "A3": ValidateAccountAlgorithmA3(blz, account10Digits); break;
                case "A4": ValidateAccountAlgorithmA4(blz, account10Digits); break;
                case "A5": ValidateAccountAlgorithmA5(blz, account10Digits); break;
                case "A6": ValidateAccountAlgorithmA6(blz, account10Digits); break;
                case "A7": ValidateAccountAlgorithmA7(blz, account10Digits); break;
                case "A8": ValidateAccountAlgorithmA8(blz, account10Digits); break;
                case "A9": ValidateAccountAlgorithmA9(blz, account10Digits); break;
                case "B0": ValidateAccountAlgorithmB0(blz, account10Digits); break;
                case "B1": ValidateAccountAlgorithmB1(blz, account10Digits); break;
                case "B2": ValidateAccountAlgorithmB2(blz, account10Digits); break;
                case "B3": ValidateAccountAlgorithmB3(blz, account10Digits); break;
                case "B4": ValidateAccountAlgorithmB4(blz, account10Digits); break;
                case "B5": ValidateAccountAlgorithmB5(blz, account10Digits); break;
                case "B6": ValidateAccountAlgorithmB6(blz, account10Digits); break;
                case "B7": ValidateAccountAlgorithmB7(blz, account10Digits); break;
                case "B8": ValidateAccountAlgorithmB8(blz, account10Digits); break;
                case "B9": ValidateAccountAlgorithmB9(blz, account10Digits); break;
                case "C0": ValidateAccountAlgorithmC0(blz, account10Digits); break;
                case "C1": ValidateAccountAlgorithmC1(blz, account10Digits); break;
                case "C2": ValidateAccountAlgorithmC2(blz, account10Digits); break;
                case "C3": ValidateAccountAlgorithmC3(blz, account10Digits); break;
                case "C4": ValidateAccountAlgorithmC4(blz, account10Digits); break;
                case "C5": ValidateAccountAlgorithmC5(blz, account10Digits); break;
                case "C6": ValidateAccountAlgorithmC6(blz, account10Digits); break;
                case "C7": ValidateAccountAlgorithmC7(blz, account10Digits); break;
                case "C8": ValidateAccountAlgorithmC8(blz, account10Digits); break;
                case "C9": ValidateAccountAlgorithmC9(blz, account10Digits); break;
                case "D0": ValidateAccountAlgorithmD0(blz, account10Digits); break;
                case "D1": ValidateAccountAlgorithmD1(blz, account10Digits); break;
                case "D2": ValidateAccountAlgorithmD2(blz, account10Digits); break;
                case "D3": ValidateAccountAlgorithmD3(blz, account10Digits); break;
                case "D4": ValidateAccountAlgorithmD4(blz, account10Digits); break;
                case "D5": ValidateAccountAlgorithmD5(blz, account10Digits); break;
                case "D6": ValidateAccountAlgorithmD6(blz, account10Digits); break;
                case "D7": ValidateAccountAlgorithmD7(blz, account10Digits); break;
                case "D8": ValidateAccountAlgorithmD8(blz, account10Digits); break;

                default: throw new BankException("argument:1401", String.Format("invalid blz '{0}' -> there is not a known validation algorithm for this blz", blz));
            }
        }

        // format a blz
        public string FormatBlz(string blz)
        {
            if (String.IsNullOrEmpty(blz)) throw new ChecksumException("argument:1406", "blz must not be empty");
            RegexChecker.ValidateBlz(blz);

            string strBlz1 = blz.Substring(0, 3);
            string strBlz2 = blz.Substring(3, 3);
            string strBlz3 = blz.Substring(6, 2);

            string formattedBlz = strBlz1 + " " + strBlz2 + " " + strBlz3;
            this.traceManager.TraceLine(formattedBlz, TraceManager.VerboseMode.VeryVerbose);
            return formattedBlz;
        }

        // retrieves the algorithm number responsible to compute and compare the checksum digit of the account
        private void GetBlzAlgorithmNumber(string blz, out string checksum, out bool validate)
        {
            if (String.IsNullOrEmpty(blz)) throw new ChecksumException("argument:1407", "blz must not be empty");

            checksum = String.Empty;
            validate = true;

            try
            {
                if ((bankDirectory == null) || (bankDirectory.Count == 0)) Load();

                object entry = this.bankDirectory[blz];
                if (entry == null) throw new BankException("argument:1402", String.Format("blz '{0}' does not exist in blz directory", blz));
                if (entry.GetType() != typeof(Bank)) throw new ChecksumException("argument:1408", String.Format("entry is of type '{0}' but must be of type '{1}'", entry.GetType().FullName, typeof(Bank).FullName));

                Bank bank = (Bank)entry;

                checksum = bank.ChecksumCode;
                if (String.IsNullOrEmpty(checksum)) throw new BankException("argument:1403", String.Format("checksum must not be empty (blz = '{0}')", blz));

                validate = !checksum.Equals(cNoValidationAlgorithm, StringComparison.CurrentCultureIgnoreCase);
            }
            catch (BankException ex)
            {
                throw ex;
            }
            catch (Exception ex)
            {
                throw new ChecksumException("argument:1409", String.Format("unexpected error when trying to retrieve checksum algorithm of blz '{0}'", blz), ex);
            }
        }

        // algorithm 00
        private void ValidateAccountAlgorithm00(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '00'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("00",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 01
        private void ValidateAccountAlgorithm01(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '01'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation01("01",                            // algorithmId
                                                   account10Digits.Substring(0, 9), // accountRelevantDigits
                                                   account10Digits[9].ToString(),   // givenChecksum
                                                   cWeighting_3_7_1,                // weighting
                                                   10,                              // checksumDivisor
                                                   cChecksumMapping_10_0,           // checksumMapping
                                                   blz,                             // blz
                                                   account10Digits                  // account10Digits
                                                  );
        }

        // algorithm 02
        private void ValidateAccountAlgorithm02(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '02'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation02("02",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_9_2,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_11_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 03
        private void ValidateAccountAlgorithm03(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '03' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation01("03",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 04
        private void ValidateAccountAlgorithm04(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '04' (by algorithm '02')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation02("04",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_2_3_4,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_11_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 05
        private void ValidateAccountAlgorithm05(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '05' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation01("05",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_7_3_1,                // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 06
        private void ValidateAccountAlgorithm06(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '06'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("06",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7,          // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 07
        private void ValidateAccountAlgorithm07(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '07' (by algorithm '02')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation02("07",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_9_A,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_11_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 08
        private void ValidateAccountAlgorithm08(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '08' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountAlgorithm00(blz, account10Digits);
        }

        // algorithm 09
        private void ValidateAccountAlgorithm09(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '09'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // for checksum code number, no algorithm has to be applied.
            traceManager.TraceLine("Info:           no algorithm needs not be applied", TraceManager.VerboseMode.VeryVerbose);
        }

        // algorithm 10
        private void ValidateAccountAlgorithm10(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '10' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("10",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_9_A,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 11
        private void ValidateAccountAlgorithm11(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '11' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("11",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_9_A,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_9_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 12
        private void ValidateAccountAlgorithm12(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '12'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // algorithm is free (not assigned)
        }

        // algorithm 13
        private void ValidateAccountAlgorithm13(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '13' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("13",                            // algorithmId
                                                     account10Digits.Substring(1, 6), // accountRelevantDigits
                                                     account10Digits[7].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch(BankException)
            {
                string account10DigitsModified = account10Digits.Substring(2) + "00";

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '13' again with modified account (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                traceManager.TraceLine(String.Format("mod. account:   {0}", account10DigitsModified), TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("13",                                    // algorithmId
                                                     account10DigitsModified.Substring(1, 6), // accountRelevantDigits
                                                     account10DigitsModified[7].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                          // weighting
                                                     10,                                      // checksumDivisor
                                                     cChecksumMapping_10_0,                   // checksumMapping
                                                     blz,                                     // blz
                                                     account10Digits                          // account10Digits
                                                    );
            }
        }

        // algorithm 14
        private void ValidateAccountAlgorithm14(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '14' (by algorithm '02')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation02("14",                            // algorithmId
                                                 account10Digits.Substring(3, 6), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7,          // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_11_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 15
        private void ValidateAccountAlgorithm15(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '15' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("15",                            // algorithmId
                                                 account10Digits.Substring(5, 4), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5,              // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 16
        private void ValidateAccountAlgorithm16(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '16' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("16",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_2_3_4,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 17
        private void ValidateAccountAlgorithm17(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '17'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // account parts
            string accountK = account10Digits.Substring(0, 1); // account type digit
            string accountS = account10Digits.Substring(1, 6); // account number
            string accountP = account10Digits.Substring(7, 1); // checksum
            string accountU = account10Digits.Substring(8, 2); // sub account

            traceManager.TraceLine("account:        KSSSSSSPUU", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("                {0}", accountK + accountS + accountP + accountU), TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits = account10Digits.Substring(1, 6);
            string strGivenChecksum = account10Digits[7].ToString();
            byte[] weighting = cWeighting_1_2;
            Hashtable checksumMapping = cChecksumMapping_10_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

            // multiply digits with weighting array
            validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(accountRelevantDigits, weighting);
            validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);
            sum -= 1;

            // compute check sum
            byte computedChecksum = (byte)(sum % 11);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(10 - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 18
        private void ValidateAccountAlgorithm18(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '18' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation01("18",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_3_9_7_1,              // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 19
        private void ValidateAccountAlgorithm19(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '19' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("19",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_9_1,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 20
        private void ValidateAccountAlgorithm20(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '20' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("20",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_9_3,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 21
        private void ValidateAccountAlgorithm21(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '21' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("21",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 22
        private void ValidateAccountAlgorithm22(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '22'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_3_1;
            byte checksumDivisor = 10;
            Hashtable checksumMapping = cChecksumMapping_10_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

            // multiply digits with weighting array
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            validationUtilities.ConsiderLowestDigitOfEachByte(accountRelevantDigits);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 23
        private void ValidateAccountAlgorithm23(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '23' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("23",                            // algorithmId
                                                 account10Digits.Substring(0, 6), // accountRelevantDigits
                                                 account10Digits[6].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7,          // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 24
        private void ValidateAccountAlgorithm24(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '24'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string accountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_1_2_3;
            byte checksumDivisor = 11;

            traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // consider exceptions to the rule
            byte[] accountDigitsModified = validationUtilities.GetByteArrayOfString(accountRelevantDigits);

            if (accountDigitsModified[0] == 3 || accountDigitsModified[0] == 4 ||
                accountDigitsModified[0] == 5 || accountDigitsModified[0] == 6)
            {
                accountDigitsModified[0] = 0;
            }

            if (accountDigitsModified[0] == 9)
            {
                accountDigitsModified[0] = 0;
                accountDigitsModified[1] = 0;
                accountDigitsModified[2] = 0;

                if (accountDigitsModified[3] == 0)
                {
                    throw new BankException("validation:3401", String.Format("assumption failed -> account '{0}' starts with digit '9', but digit '{1}' at position 4 equals to zero", account10Digits, accountDigitsModified[3].ToString()));
                }
            }

            validationUtilities.TraceTemporaryResult(accountDigitsModified);

            // forget leading zeroes           
            string account10DigitsModified = validationUtilities.GetStringOfByteArray(accountDigitsModified);

            int posFirstNonZeroDigit = account10DigitsModified.IndexOfAny(c123456789);
            if (posFirstNonZeroDigit > -1)
            {
                // multiply digits with weighting array
                validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(accountDigitsModified, weighting, posFirstNonZeroDigit); // start with first non-zero digit
                validationUtilities.AddCyclicFromLeftToRightDigitByDigit(accountDigitsModified, weighting, posFirstNonZeroDigit);
            }

            validationUtilities.ComputeRemainderForEachDigit(accountDigitsModified, checksumDivisor);
            int sum = validationUtilities.AddAllValues(accountDigitsModified);

            // compute check sum
            byte computedChecksum = (byte)(sum % 10);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte bytGivenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, bytGivenChecksum, blz, account10Digits);
        }

        // algorithm 25
        private void ValidateAccountAlgorithm25(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '25'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string accountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_2_3_4_5_6_7_8_9;
            byte checksumDivisor = 11;
            Hashtable checksumMapping = cChecksumMapping_10_0_11_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountDigits = validationUtilities.GetByteArrayOfString(accountRelevantDigits);
            validationUtilities.TraceTemporaryResult(accountDigits);

            // multiply digits with weighting array
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // consider working digit
            if (computedChecksum == 1 && accountDigits[1] != 8 && accountDigits[1] != 9)
            {
                // checksum can only be used for working digit 8 and 9 (the second digit from left to right represents the working digit)
                throw new BankException("validation:3402", String.Format("parity failure -> computed checksum = '{0}', but working digit '{1}' does not equal to '8' or '9'", computedChecksum.ToString(), accountDigits[1].ToString()));
            }

            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 26
        private void ValidateAccountAlgorithm26(string blz, string account10Digits)
        {
            // modify account due to rules
            string account10DigitsModified = account10Digits;

            if (account10Digits.StartsWith("00"))
            {
                account10DigitsModified = account10Digits.Substring(2) + "00";
            }

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '26' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("26",                                    // algorithmId
                                                 account10DigitsModified.Substring(0, 7), // accountRelevantDigits
                                                 account10DigitsModified[7].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_2,                // weighting
                                                 11,                                      // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,              // checksumMapping
                                                 blz,                                     // blz
                                                 account10Digits                          // account10Digits
                                                );
        }

        // algorithm 27
        private void ValidateAccountAlgorithm27(string blz, string account10Digits)
        {
            if (account10Digits[0] == '0')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '27' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '27' (by algorithm 'M10H')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // algorithm M10H (iterated transformation)
                string accountRelevantDigits = account10Digits.Substring(0, 9);
                string strGivenChecksum = account10Digits[9].ToString();
                byte checksumDivisor = 10;
                Hashtable checksumMapping = cChecksumMapping_10_0;

                traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountDigits = validationUtilities.GetByteArrayOfString(accountRelevantDigits);
                validationUtilities.TraceTemporaryResult(accountDigits);
                validationUtilities.TransformDigitByDigitFromRightToLeft(accountDigits, cTransformationMeh);
                validationUtilities.TraceTemporaryResult(accountDigits);
                int sum = validationUtilities.AddAllValues(accountDigits);

                // compute check sum
                byte computedChecksum = (byte)(sum % checksumDivisor);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                computedChecksum = (byte)(checksumDivisor - computedChecksum);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                MapChecksum(checksumMapping, ref computedChecksum);
                traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
        }

        // algorithm 28
        private void ValidateAccountAlgorithm28(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '28' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("28",                            // algorithmId
                                                 account10Digits.Substring(0, 7), // accountRelevantDigits
                                                 account10Digits[7].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8,        // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 29
        private void ValidateAccountAlgorithm29(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '29' (by algorithm 'M10H')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // algorithm M10H (iterated transformation)
            string accountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte checksumDivisor = 10;
            Hashtable checksumMapping = cChecksumMapping_10_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountDigits = validationUtilities.GetByteArrayOfString(accountRelevantDigits);
            validationUtilities.TraceTemporaryResult(accountDigits);
            validationUtilities.TransformDigitByDigitFromRightToLeft(accountDigits, cTransformationMeh);
            validationUtilities.TraceTemporaryResult(accountDigits);
            int sum = validationUtilities.AddAllValues(accountDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 30
        private void ValidateAccountAlgorithm30(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '30' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("30",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_0_0_0_0_1_2_1_2,    // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 31
        private void ValidateAccountAlgorithm31(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '31'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string accountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_9_8_7_6_5_4_3_2_1;
            byte checksumDivisor = 11;
            Hashtable checksumMapping = cChecksumMapping_11_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountDigits = validationUtilities.GetByteArrayOfString(accountRelevantDigits);
            validationUtilities.TraceTemporaryResult(accountDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // consider working digit
            if (computedChecksum == 10) throw new BankException("validation:3403", String.Format("parity failure -> computed checksum = '{0}', i.e. account '{1}' is invalid", computedChecksum.ToString(), account10Digits));

            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: " + computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: " + computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 32
        private void ValidateAccountAlgorithm32(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '32' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("32",                            // algorithmId
                                                 account10Digits.Substring(3, 6), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7,          // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 33
        private void ValidateAccountAlgorithm33(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '33' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("33",                            // algorithmId
                                                 account10Digits.Substring(4, 5), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6,            // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 34
        private void ValidateAccountAlgorithm34(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '34' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("34",                            // algorithmId
                                                 account10Digits.Substring(0, 7), // accountRelevantDigits
                                                 account10Digits[7].ToString(),   // givenChecksum
                                                 cWeighting_2_4_8_5_A_9_7,        // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 35
        private void ValidateAccountAlgorithm35(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '35'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string accountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_2_3_4_5_6_7_8_9_A;
            byte checksumDivisor = 11;

            traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountDigits = validationUtilities.GetByteArrayOfString(accountRelevantDigits);
            validationUtilities.TraceTemporaryResult(accountDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            if (computedChecksum == 10)
            {
                if (account10Digits[8] == account10Digits[9]) 
                {
                    traceManager.Trace(String.Format("final checksum: {0} --> OK (last both digits are identical)", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose, true);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose, true);
                }
                else throw new BankException("validation:3404", String.Format("parity failure -> computed checksum = '{0}', but last both digits of account '{1}' are not identical", computedChecksum.ToString(), account10Digits));
            }
            else
            {
                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
        }

        // algorithm 36
        private void ValidateAccountAlgorithm36(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '36' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("36",                            // algorithmId
                                                 account10Digits.Substring(5, 4), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_4_8_5,              // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 37
        private void ValidateAccountAlgorithm37(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '37' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("37",                            // algorithmId
                                                 account10Digits.Substring(4, 5), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_4_8_5_A,            // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 38
        private void ValidateAccountAlgorithm38(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '38' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("38",                            // algorithmId
                                                 account10Digits.Substring(3, 6), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_4_8_5_A_9,          // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 39
        private void ValidateAccountAlgorithm39(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '39' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("39",                            // algorithmId
                                                 account10Digits.Substring(2, 7), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_4_8_5_A_9_7,        // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 40
        private void ValidateAccountAlgorithm40(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '40' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("40",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_4_8_5_A_9_7_3_6,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 41
        private void ValidateAccountAlgorithm41(string blz, string account10Digits)
        {
            if (account10Digits[3] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '41' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("41",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '41' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("41",                            // algorithmId
                                                     account10Digits.Substring(0, 9), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm 42
        private void ValidateAccountAlgorithm42(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '42' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("42",                            // algorithmId
                                                 account10Digits.Substring(1, 8), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_9,      // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 43
        private void ValidateAccountAlgorithm43(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '43'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_1_2_3_4_5_6_7_8_9;
            byte checksumDivisor = 10;
            Hashtable checksumMapping = cChecksumMapping_10_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 44
        private void ValidateAccountAlgorithm44(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '44' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("44",                            // algorithmId
                                                 account10Digits.Substring(4, 5), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_4_8_5_A_0_0_0_0,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 45
        private void ValidateAccountAlgorithm45(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '45'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // validate rules
            if (account10Digits[0] == '0')
            {
                // account does not contain any checksum
                traceManager.TraceLine("Checksum:        --> OK (account contains digit '0' at first position)", TraceManager.VerboseMode.VeryVerbose);
                return;
            }
            else if (account10Digits[4] == '1')
            {
                // account does not contain any checksum
                traceManager.TraceLine("Checksum:        --> OK (account contains digit '1' at position 5)", TraceManager.VerboseMode.VeryVerbose);
                return;
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '45' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("45",                                // algorithmId
                                                       account10Digits.Substring(0, 9),   // accountRelevantDigits
                                                       account10Digits[9].ToString(),    // givenChecksum
                                                       cWeighting_2_1,                // weighting
                                                       10,                                  // checksumDivisor
                                                       cChecksumMapping_10_0,            // checksumMapping
                                                       blz,                              // blz
                                                       account10Digits                   // account10Digits
                                                       );
            }
        }

        // algorithm 46
        private void ValidateAccountAlgorithm46(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '46' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("46",                            // algorithmId
                                                 account10Digits.Substring(2, 5), // accountRelevantDigits
                                                 account10Digits[7].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6,            // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 47
        private void ValidateAccountAlgorithm47(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '47' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("47",                            // algorithmId
                                                 account10Digits.Substring(3, 5), // accountRelevantDigits
                                                 account10Digits[8].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6,            // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 48
        private void ValidateAccountAlgorithm48(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '48' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("48",                            // algorithmId
                                                 account10Digits.Substring(2, 6), // accountRelevantDigits
                                                 account10Digits[8].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7,          // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 49
        private void ValidateAccountAlgorithm49(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '49' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '49' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm01(blz, account10Digits);
            }
        }

        // algorithm 50
        private void ValidateAccountAlgorithm50(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '50' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("50",                            // algorithmId
                                                     account10Digits.Substring(0, 6), // accountRelevantDigits
                                                     account10Digits[6].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                if (account10Digits.TrimStart(c0).Length + 3 > cMaxDigitsAccount) throw new BankException("validation:3405", "algorithm is not applicable since sub account '000' is missing but account contains more digits than allowed");

                string strAccount10DigitsModified = account10Digits.Substring(3) + "000";

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '50' again (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("50",                          // algorithmId
                                                     strAccount10DigitsModified,    // accountRelevantDigits
                                                     account10Digits[6].ToString(), // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,        // weighting
                                                     11,                            // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,    // checksumMapping
                                                     blz,                           // blz
                                                     account10Digits                // account10Digits
                                                    );
            }
        }

        // algorithm 51
        private void ValidateAccountAlgorithm51(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '51A' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("51A",                           // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '51B' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                try
                {
                    ValidateAccountInternalComputation06("51B",                           // algorithmId
                                                         account10Digits.Substring(4, 5), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6,            // weighting
                                                         11,                              // checksumDivisor
                                                         cChecksumMapping_10_0_11_0,      // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    if (account10Digits[2] == '9')
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '51'", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation51(blz, account10Digits);
                    }
                    else
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '51C' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation06("51C",                           // algorithmId
                                                             account10Digits.Substring(4, 5), // accountRelevantDigits
                                                             account10Digits[9].ToString(),   // givenChecksum
                                                             cWeighting_2_3_4_5_6,            // weighting
                                                             7,                               // checksumDivisor
                                                             cChecksumMapping_7_0,            // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                            );
                    }
                }
            }
        }

        // algorithm 52
        private void ValidateAccountAlgorithm52(string blz, string account10Digits)
        {
            // validating rules
            if (blz[3] != '5') throw new BankException("validation:3406", String.Format("algorithm is not applicable because blz '{0}' does not contain digit '5' at position 4", blz));

            if (account10Digits[0] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '52' (by algorithm '20')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm20(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '52' (by algorithm 'ESER')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // build ESER account
                string eserAccount = "";
                string eserLeftPart = "";
                string eserMidPart = "";
                string eserRightPart = "";

                validationUtilities.GetEserFor8DigitAccount(blz, account10Digits, out eserAccount, out eserLeftPart, out eserMidPart, out eserRightPart);

                traceManager.TraceLine(String.Format("Eser:           {0}-{1}-{2}", eserLeftPart, eserMidPart, eserRightPart), TraceManager.VerboseMode.VeryVerbose);

                string accountRelevantDigits = eserAccount;
                string strGivenChecksum = account10Digits.TrimStart(c0)[1].ToString();
                byte[] weighting = cWeighting_2_4_8_5_A_9_7_3_6_1_2_4;
                byte checksumDivisor = 11;

                traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountDigits = validationUtilities.GetByteArrayOfString(eserAccount);
                accountDigits[5] = 0; // checksum position must be set to zero
                validationUtilities.TraceTemporaryResult(accountDigits);
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountDigits, weighting);
                int sum = validationUtilities.AddAllValues(accountDigits);

                byte rest = (byte)(sum % checksumDivisor);
                byte checksumWeighting = weighting[(eserMidPart + eserRightPart).Length - 2];
                traceManager.TraceLine(String.Format("weight:         {0}", checksumWeighting.ToString()), TraceManager.VerboseMode.VeryVerbose);

                // compute check sum
                byte checksum = 0;
                int watchDog = 0;
                const int cWatchDogLimit = 24;

                while (((rest + checksum * checksumWeighting) % checksumDivisor != 10) && (watchDog < cWatchDogLimit))
                {
                    traceManager.TraceLine(String.Format("                                           {0} + {1} * {2} = {3} mod {4} = {5}", rest.ToString(), checksum.ToString(), checksumWeighting.ToString(), (rest + checksum * checksumWeighting).ToString(), checksumDivisor.ToString(), ((rest + checksum * checksumWeighting) % checksumDivisor).ToString()), TraceManager.VerboseMode.VeryVeryVerbose);

                    checksum++;
                    watchDog++;
                }

                traceManager.TraceLine(String.Format("                                           {0} + {1} * {2} = {3} mod {4} = {5}", rest.ToString(), checksum.ToString(), checksumWeighting.ToString(), (rest + checksum * checksumWeighting).ToString(), checksumDivisor.ToString(), ((rest + checksum * checksumWeighting) % checksumDivisor).ToString()), TraceManager.VerboseMode.VeryVeryVerbose);
                if (watchDog >= cWatchDogLimit) throw new BankException("validation:3407", String.Format("infinite loop -> account = '{0}', product sum = '{1}'", account10Digits, sum.ToString()));

                // compute check sum
                byte computedChecksum = checksum;
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
        }

        // algorithm 53
        private void ValidateAccountAlgorithm53(string blz, string account10Digits)
        {
            // validating rules
            if (blz[3] != '5') throw new BankException("validation:3408", String.Format("algorithm is not applicable because blz '{0}' does not contain digit '5' at position 4", blz));

            if (account10Digits[0] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '53' (by algorithm '20')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm20(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '53' (by algorithm 'ESER')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // build ESER account
                string eserAccount = "";
                string eserLeftPart = "";
                string eserMidPart = "";
                string eserRightPart = "";

                validationUtilities.GetEserFor9DigitAccount(blz, account10Digits, out eserAccount, out eserLeftPart, out eserMidPart, out eserRightPart);

                traceManager.TraceLine(String.Format("Eser:           {0}-{1}-{2}", eserLeftPart, eserMidPart, eserRightPart), TraceManager.VerboseMode.VeryVerbose);

                string accountRelevantDigits = eserAccount;
                string strGivenChecksum = account10Digits.TrimStart(c0)[2].ToString();
                byte[] weighting = cWeighting_2_4_8_5_A_9_7_3_6_1_2_4;
                byte checksumDivisor = 11;

                traceManager.TraceLine(String.Format("relevant:       {0}", accountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountDigits = validationUtilities.GetByteArrayOfString(eserAccount);
                accountDigits[5] = 0; // checksum position must be set to zero
                validationUtilities.TraceTemporaryResult(accountDigits);
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountDigits, weighting);
                int sum = validationUtilities.AddAllValues(accountDigits);

                byte rest = (byte)(sum % checksumDivisor);
                byte checksumWeighting = weighting[(eserMidPart + eserRightPart).Length - 2];

                traceManager.TraceLine(String.Format("weight:         {0}", checksumWeighting.ToString()), TraceManager.VerboseMode.VeryVerbose);

                // compute check sum
                byte checksum = 0;
                int watchDog = 0;
                const int cWatchDogLimit = 24;

                while (((rest + checksum * checksumWeighting) % checksumDivisor != 10) && (watchDog < cWatchDogLimit))
                {
                    traceManager.TraceLine(String.Format("                                           {0} + {1} * {2} = {3} mod {4} = {5}", rest.ToString(), checksum.ToString(), checksumWeighting.ToString(), (rest + checksum * checksumWeighting).ToString(), checksumDivisor.ToString(), ((rest + checksum * checksumWeighting) % checksumDivisor).ToString()), TraceManager.VerboseMode.VeryVeryVerbose);

                    checksum++;
                    watchDog++;
                }

                traceManager.TraceLine(String.Format("                                           {0} + {1} * {2} = {3} mod {4} = {5}", rest.ToString(), checksum.ToString(), checksumWeighting.ToString(), (rest + checksum * checksumWeighting).ToString(), checksumDivisor.ToString(), ((rest + checksum * checksumWeighting) % checksumDivisor).ToString()), TraceManager.VerboseMode.VeryVeryVerbose);
                if (watchDog >= cWatchDogLimit) throw new BankException("validation:3409", String.Format("infinite loop -> account = '{0}', product sum = '{1}'", account10Digits, sum.ToString()));

                // compute check sum
                byte computedChecksum = checksum;
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
        }

        // algorithm 54
        private void ValidateAccountAlgorithm54(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '54'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // validate rules
            if (account10Digits.TrimStart(c0).Length != cMaxDigitsAccount) throw new BankException("validation:3410", String.Format("algorithm is not applicable since account contains less than {0} digits", cMaxDigitsAccount.ToString()));
            if (!account10Digits.StartsWith("49")) throw new BankException("validation:3411", "algorithm is not applicable since account does not start with '49'");

            string strAccountRelevantDigits = account10Digits.Substring(2, 7);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_2_3_4_5_6_7_2;
            byte checksumDivisor = 11;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            if (computedChecksum == 11 || computedChecksum == 10) throw new BankException("validation:3412", String.Format("parity failure -> checksum '{0}' consists of more than one digit", computedChecksum.ToString()));
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 55
        private void ValidateAccountAlgorithm55(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '55' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("55",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6_7_8_7_8,    // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 56
        private void ValidateAccountAlgorithm56(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '56'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits = account10Digits.Substring(0, 9);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_2_3_4_5_6_7_2_3_4;
            byte checksumDivisor = 11;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            if (account10Digits[0] == '9')
            {
                if (computedChecksum == 10) computedChecksum = 7;
                else if (computedChecksum == 11) computedChecksum = 8;
            }
            else
            {
                if (computedChecksum == 11 || computedChecksum == 10) throw new BankException("validation:3413", String.Format("parity failure -> checksum '{0}' consists of more than one digit", computedChecksum.ToString()));
            }

            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 57
        private void ValidateAccountAlgorithm57(string blz, string account10Digits)
        {
            // validate rules
            string firstTwoDigits = account10Digits.Substring(0, 2);
            string firstSixDigits = account10Digits.Substring(0, 6);

            traceManager.TraceLine(String.Format("                first two digits are '{0}'", firstTwoDigits), TraceManager.VerboseMode.VeryVerbose);

            if (firstTwoDigits.CompareTo("00") == 0)
            {
                throw new BankException("validation:3414", String.Format("parity failure -> first two digits are '{0}'", firstTwoDigits));
            }
            else if (firstTwoDigits.CompareTo("51") == 0 ||
                     firstTwoDigits.CompareTo("55") == 0 ||
                     firstTwoDigits.CompareTo("61") == 0 ||
                     firstTwoDigits.CompareTo("64") == 0 ||
                     firstTwoDigits.CompareTo("65") == 0 ||
                     firstTwoDigits.CompareTo("66") == 0 ||
                     firstTwoDigits.CompareTo("70") == 0 ||
                     firstTwoDigits.CompareTo("73") == 0 ||
                     firstTwoDigits.CompareTo("75") == 0 ||
                     firstTwoDigits.CompareTo("76") == 0 ||
                     firstTwoDigits.CompareTo("77") == 0 ||
                     firstTwoDigits.CompareTo("78") == 0 ||
                     firstTwoDigits.CompareTo("79") == 0 ||
                     firstTwoDigits.CompareTo("80") == 0 ||
                     firstTwoDigits.CompareTo("81") == 0 ||
                     firstTwoDigits.CompareTo("82") == 0 ||
                     firstTwoDigits.CompareTo("88") == 0 ||
                     firstTwoDigits.CompareTo("94") == 0 ||
                     firstTwoDigits.CompareTo("95") == 0)
            {
                // variant 1
                if ((firstSixDigits.CompareTo("777777") == 0) ||
                    (firstSixDigits.CompareTo("888888") == 0))
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '57' (variant 1 by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm09(blz, account10Digits);

                    traceManager.TraceLine(String.Format("            --> OK (first six digits are '{0}')", firstSixDigits), TraceManager.VerboseMode.VeryVerbose);
                    return;
                }
                else
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '57' (variant 1 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("57",                            // algorithmId
                                                         account10Digits.Substring(0, 9), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_1_2,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
            }
            else if (firstTwoDigits.CompareTo("32") == 0 ||
                     firstTwoDigits.CompareTo("33") == 0 ||
                     firstTwoDigits.CompareTo("34") == 0 ||
                     firstTwoDigits.CompareTo("35") == 0 ||
                     firstTwoDigits.CompareTo("36") == 0 ||
                     firstTwoDigits.CompareTo("37") == 0 ||
                     firstTwoDigits.CompareTo("38") == 0 ||
                     firstTwoDigits.CompareTo("39") == 0 ||
                     firstTwoDigits.CompareTo("41") == 0 ||
                     firstTwoDigits.CompareTo("42") == 0 ||
                     firstTwoDigits.CompareTo("43") == 0 ||
                     firstTwoDigits.CompareTo("44") == 0 ||
                     firstTwoDigits.CompareTo("45") == 0 ||
                     firstTwoDigits.CompareTo("46") == 0 ||
                     firstTwoDigits.CompareTo("47") == 0 ||
                     firstTwoDigits.CompareTo("48") == 0 ||
                     firstTwoDigits.CompareTo("49") == 0 ||
                     firstTwoDigits.CompareTo("52") == 0 ||
                     firstTwoDigits.CompareTo("53") == 0 ||
                     firstTwoDigits.CompareTo("54") == 0 ||
                     firstTwoDigits.CompareTo("56") == 0 ||
                     firstTwoDigits.CompareTo("57") == 0 ||
                     firstTwoDigits.CompareTo("58") == 0 ||
                     firstTwoDigits.CompareTo("59") == 0 ||
                     firstTwoDigits.CompareTo("60") == 0 ||
                     firstTwoDigits.CompareTo("62") == 0 ||
                     firstTwoDigits.CompareTo("63") == 0 ||
                     firstTwoDigits.CompareTo("67") == 0 ||
                     firstTwoDigits.CompareTo("68") == 0 ||
                     firstTwoDigits.CompareTo("69") == 0 ||
                     firstTwoDigits.CompareTo("71") == 0 ||
                     firstTwoDigits.CompareTo("72") == 0 ||
                     firstTwoDigits.CompareTo("74") == 0 ||
                     firstTwoDigits.CompareTo("83") == 0 ||
                     firstTwoDigits.CompareTo("84") == 0 ||
                     firstTwoDigits.CompareTo("85") == 0 ||
                     firstTwoDigits.CompareTo("86") == 0 ||
                     firstTwoDigits.CompareTo("87") == 0 ||
                     firstTwoDigits.CompareTo("89") == 0 ||
                     firstTwoDigits.CompareTo("90") == 0 ||
                     firstTwoDigits.CompareTo("92") == 0 ||
                     firstTwoDigits.CompareTo("93") == 0 ||
                     firstTwoDigits.CompareTo("96") == 0 ||
                     firstTwoDigits.CompareTo("97") == 0 ||
                     firstTwoDigits.CompareTo("98") == 0)
            {
                // variant 2
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '57' (variant 2 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("00",                              // algorithmId
                                                     account10Digits.Substring(0, 2) +
                                                     account10Digits.Substring(3, 7),   // accountRelevantDigits
                                                     account10Digits[2].ToString(),     // givenChecksum
                                                     cWeighting_1_2,                    // weighting
                                                     10,                                // checksumDivisor
                                                     cChecksumMapping_10_0,             // checksumMapping
                                                     blz,                               // blz
                                                     account10Digits                    // account10Digits
                                                    );
            }
            else if (firstTwoDigits.CompareTo("40") == 0 ||
                     firstTwoDigits.CompareTo("50") == 0 ||
                     firstTwoDigits.CompareTo("91") == 0 ||
                     firstTwoDigits.CompareTo("99") == 0)
            {
                // variant 3
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '57' (variant 3 by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm09(blz, account10Digits);

            }
            else if (firstTwoDigits.CompareTo("01") >= 0 &&
                     firstTwoDigits.CompareTo("31") <= 0)
            {
                // variant 4
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '57' (variant 4)", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                string digits3To4 = account10Digits.Substring(2, 2);
                string digits7To9 = account10Digits.Substring(6, 3);

                traceManager.TraceLine(String.Format("                digits 3 to 4 are '{0}'", digits3To4), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(String.Format("                digits 7 to 9 are '{0}'", digits7To9), TraceManager.VerboseMode.VeryVerbose);

                if ((digits3To4.CompareTo("01") >= 0 && digits3To4.CompareTo("12") <= 0) &&
                    (digits7To9.CompareTo("500") < 0))
                {
                    traceManager.TraceLine("Checksum:        --> OK (digits 3 to 4 and 7 to 9 are correctly positioned to their valid values)", TraceManager.VerboseMode.VeryVerbose);
                    return;
                }
                else if (account10Digits.CompareTo("0185125434") == 0)
                {
                    traceManager.TraceLine(String.Format("Checksum:        --> OK (account number is '{0}')", account10Digits), TraceManager.VerboseMode.VeryVerbose);
                    return;
                }
                else
                {
                    throw new BankException("validation:3415", "assumption failed -> digits 3 to 4 and 7 to 9 are not correctly positioned to their valid values");
                }
            }
            else
            {
                throw new BankException("validation:3416", String.Format("assumption failed -> first two digits are '{0}'", firstTwoDigits));
            }
        }

        // algorithm 58
        private void ValidateAccountAlgorithm58(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '58' (by algorithm '02')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // validate rules
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);

            if (accountWithoutLeadingZeroes.Length < 6) throw new BankException("validation:3417", String.Format("algorithm is not applicable since account consists of only {0} digits (must be at least 6 digits)", accountWithoutLeadingZeroes.Length.ToString()));

            ValidateAccountInternalComputation02("58",                            // algorithmId
                                                 account10Digits.Substring(4, 5), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_3_4_5_6,            // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_11_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 59
        private void ValidateAccountAlgorithm59(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '59' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // validate rules
            if (account10Digits.StartsWith("00"))
            {
                traceManager.TraceLine("Checksum:       OK (first two digits are '00')", TraceManager.VerboseMode.VeryVerbose);
            }
            else
            {
                ValidateAccountInternalComputation00("59",                            // algorithmId
                                                     account10Digits.Substring(0, 9), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm 60
        private void ValidateAccountAlgorithm60(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '60' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("60",                            // algorithmId
                                                 account10Digits.Substring(2, 7), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 61
        private void ValidateAccountAlgorithm61(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '61'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // account parts
            string accountBBB = account10Digits.Substring(0, 3);   // banking site
            string accountSSSS = account10Digits.Substring(3, 4);   // account base number
            string accountP = account10Digits.Substring(7, 1);   // checksum
            string accountA = account10Digits.Substring(8, 1);   // type digit
            string accountU = account10Digits.Substring(9, 1);   // sub account

            traceManager.TraceLine("account:        BBBSSSSPAU", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("                {0}{1}{2}{3}{4}", accountBBB, accountSSSS, accountP, accountA, accountU), TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits;
            if (account10Digits[8] == '8') strAccountRelevantDigits = account10Digits.Substring(0, 7) + account10Digits.Substring(8, 2);
            else strAccountRelevantDigits = account10Digits.Substring(0, 7);
            string strGivenChecksum = account10Digits[7].ToString();
            byte[] weighting = cWeighting_2_1;
            byte checksumDivisor = 10;
            Hashtable checksumMapping = cChecksumMapping_10_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 62
        private void ValidateAccountAlgorithm62(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '62'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits = account10Digits.Substring(2, 5);
            string strGivenChecksum = account10Digits[7].ToString();
            byte[] weighting = cWeighting_2_1;
            byte checksumDivisor = 10;
            Hashtable checksumMapping = cChecksumMapping_10_0;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 63
        private void ValidateAccountAlgorithm63(string blz, string account10Digits)
        {
            // validate rules
            if (account10Digits[0] != '0') throw new BankException("validation:3418", String.Format("algorithm is not applicable since first digit '{0}' is not equal to zero", account10Digits[0]));

            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '63'", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation63("63",                            // algorithmId
                                                     account10Digits.Substring(1, 6), // accountRelevantDigits
                                                     account10Digits[7].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                if (account10Digits.Substring(0, 2).CompareTo("00") != 0) throw new BankException("validation:3419", "algorithm is not applicable since sub account '00' is not specified and account has not been filled up with leading zeroes '000'");

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '63' with modified account", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation63("63",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm 64
        private void ValidateAccountAlgorithm64(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '64' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation06("64",                            // algorithmId
                                                 account10Digits.Substring(0, 6), // accountRelevantDigits
                                                 account10Digits[6].ToString(),   // givenChecksum
                                                 cWeighting_9_A_5_8_4_2,          // weighting
                                                 11,                              // checksumDivisor
                                                 cChecksumMapping_10_0_11_0,      // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 65
        private void ValidateAccountAlgorithm65(string blz, string account10Digits)
        {
            if (account10Digits[8] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '65' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("65",                              // algorithmId
                                                     account10Digits.Substring(0, 7) +
                                                     account10Digits.Substring(8, 2),   // accountRelevantDigits
                                                     account10Digits[7].ToString(),     // givenChecksum
                                                     cWeighting_2_1,                    // weighting
                                                     10,                                // checksumDivisor
                                                     cChecksumMapping_10_0,             // checksumMapping
                                                     blz,                               // blz
                                                     account10Digits                    // account10Digits
                                                    );
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '65' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("65",                            // algorithmId
                                                     account10Digits.Substring(0, 7), // accountRelevantDigits
                                                     account10Digits[7].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm 66
        private void ValidateAccountAlgorithm66(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '66'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // validate rules
            if (account10Digits[0] != '0') throw new BankException("validation:3420", String.Format("algorithm is not applicable since first digit '{0}' is not equal to zero", account10Digits[0]));

            string strAccountRelevantDigits = account10Digits.Substring(1, 8);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_2_3_4_5_6_0_0_7;
            byte checksumDivisor = 11;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            if (computedChecksum == 0) computedChecksum = 1;
            else if (computedChecksum == 1) computedChecksum = 0;
            else computedChecksum = (byte)(checksumDivisor - computedChecksum);

            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 67
        private void ValidateAccountAlgorithm67(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '67' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("67",                            // algorithmId
                                                 account10Digits.Substring(0, 7), // accountRelevantDigits
                                                 account10Digits[7].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 68
        private void ValidateAccountAlgorithm68(string blz, string account10Digits)
        {
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);

            if (accountWithoutLeadingZeroes.Length == 10)
            {
                if (account10Digits[3] != '9') throw new BankException("validation:3421", String.Format("algorithm is not applicable since 4th digit '{0}' is not equal to '9'", account10Digits[3]));

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '68' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("68",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else if (accountWithoutLeadingZeroes.Length == 9 && account10Digits.StartsWith("04"))
            {
                traceManager.TraceLine("Checksum:        --> OK (account is in interval 400 000 000 ... 499 999 999 and does not contain any checksum)", TraceManager.VerboseMode.VeryVerbose);
            }
            else if (accountWithoutLeadingZeroes.Length >= 6)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '68' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("68",                            // algorithmId
                                                         account10Digits.Substring(0, 9), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '68' with modified account number (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("68",                              // algorithmId
                                                         account10Digits.Substring(0, 2) +
                                                         account10Digits.Substring(4, 5),   // accountRelevantDigits
                                                         account10Digits[9].ToString(),     // givenChecksum
                                                         cWeighting_2_1,                    // weighting
                                                         10,                                // checksumDivisor
                                                         cChecksumMapping_10_0,             // checksumMapping
                                                         blz,                               // blz
                                                         account10Digits                    // account10Digits
                                                        );
                }
            }
            else
            {
                throw new BankException("validation:3422", String.Format("algorithm is not applicable since account consists of only {0} digits", accountWithoutLeadingZeroes.Length));
            }
        }

        // algorithm 69
        private void ValidateAccountAlgorithm69(string blz, string account10Digits)
        {
            if (account10Digits.CompareTo("9300000000") >= 0 && account10Digits.CompareTo("9399999999") <= 0)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '69' (by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm09(blz, account10Digits);
            }
            else if ((account10Digits.CompareTo("9700000000") >= 0) && (account10Digits.CompareTo("9799999999") <= 0)) 
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '69'", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation69("69",                            // algorithmId
                                                     account10Digits.Substring(0, 9), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '69' (by algorithm '28')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm28(blz, account10Digits);
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '69' with modified account number", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation69("69",                            // algorithmId
                                                         account10Digits.Substring(0, 9), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
            }
        }

        // algorithm 70
        private void ValidateAccountAlgorithm70(string blz, string account10Digits)
        {
            if (account10Digits[3] == '5' ||
                (account10Digits[3] == '6' && account10Digits[4] == '9'))
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '70' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("70",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '70' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("70",                            // algorithmId
                                                     account10Digits.Substring(0, 9), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm 71
        private void ValidateAccountAlgorithm71(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '71'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits = account10Digits.Substring(1, 6);
            string strGivenChecksum = account10Digits[9].ToString();
            byte[] weighting = cWeighting_6_5_4_3_2_1;
            byte checksumDivisor = 11;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            if (computedChecksum == 0) computedChecksum = 0;
            else if (computedChecksum == 1) computedChecksum = 1;
            else computedChecksum = (byte)(checksumDivisor - computedChecksum);

            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 72
        private void ValidateAccountAlgorithm72(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '72' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("72",                            // algorithmId
                                                 account10Digits.Substring(3, 6), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 73
        private void ValidateAccountAlgorithm73(string blz, string account10Digits)
        {
            if (account10Digits[2] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '73' (by algorithm '51')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation51(blz, account10Digits);
            }
            else
            {
                try
                {
                    // variant 1
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '73' (variant 1 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("73",                            // algorithmId
                                                         account10Digits.Substring(3, 6), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '73' (variant 2 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    try
                    {
                        // variant 2
                        ValidateAccountInternalComputation00("73",                            // algorithmId
                                                             account10Digits.Substring(4, 5), // accountRelevantDigits
                                                             account10Digits[9].ToString(),   // givenChecksum
                                                             cWeighting_2_1,                  // weighting
                                                             10,                              // checksumDivisor
                                                             cChecksumMapping_10_0,           // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                            );
                    }
                    catch (BankException)
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '73' (variant 3 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        // variant 3
                        ValidateAccountInternalComputation00("73",                            // algorithmId
                                                             account10Digits.Substring(4, 5), // accountRelevantDigits
                                                             account10Digits[9].ToString(),   // givenChecksum
                                                             cWeighting_2_1,                  // weighting
                                                             7,                               // checksumDivisor
                                                             cChecksumMapping_7_0,            // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                            );
                    }
                }
            }
        }

        // algorithm 74
        private void ValidateAccountAlgorithm74(string blz, string account10Digits)
        {
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);

            if (accountWithoutLeadingZeroes.Length < 2)
            {
                throw new BankException("validation:3423", String.Format("algorithm is not applicable since account consists of only {0} digits", accountWithoutLeadingZeroes.Length.ToString()));
            }

            if (accountWithoutLeadingZeroes.Length == 6)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '74' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("74",                            // algorithmId
                                                         account10Digits.Substring(0, 9), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '74' again", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    string strAccountRelevantDigits = account10Digits.Substring(0, 9);
                    string strGivenChecksum = account10Digits[9].ToString();
                    byte[] weighting = cWeighting_2_1;

                    traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);

                    // convert digits into array of bytes
                    byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
                    validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                    validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
                    int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                    // compute check sum
                    byte rest = (byte)(sum % 5);
                    byte computedChecksum = rest;
                    if (rest > 0) computedChecksum = (byte)(5 - rest);

                    traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                    // compare computed checksum with given checksum
                    byte givenChecksum = byte.Parse(strGivenChecksum);
                    traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                    CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
                }
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '74' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("74",                            // algorithmId
                                                     account10Digits.Substring(0, 9), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm 75
        private void ValidateAccountAlgorithm75(string blz, string account10Digits)
        {
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);

            if (accountWithoutLeadingZeroes.Length == 6 || accountWithoutLeadingZeroes.Length == 7)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '75' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("75",                            // algorithmId
                                                     account10Digits.Substring(4, 5), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else if (accountWithoutLeadingZeroes.Length == 9)
            {
                if (account10Digits[1] == '9')
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '75' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("75",                            // algorithmId
                                                         account10Digits.Substring(2, 5), // accountRelevantDigits
                                                         account10Digits[7].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                else
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '75' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("75",                            // algorithmId
                                                         account10Digits.Substring(1, 5), // accountRelevantDigits
                                                         account10Digits[6].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                         );
                }
            }
            else
            {
                throw new BankException("validation:3424", String.Format("algorithm is not applicable since account consists of only {0} digits (must be either 6, 7 or 9 digits)", accountWithoutLeadingZeroes.Length));
            }
        }

        // algorithm 76
        private void ValidateAccountAlgorithm76(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '76'", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation76("76",                                          // algorithmId
                                                     account10Digits.Substring(1, 6).TrimStart(c0), // accountRelevantDigits
                                                     account10Digits[7].ToString(),                 // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,                        // weighting
                                                     11,                                            // checksumDivisor
                                                     null,                                          // checksumMapping
                                                     blz,                                           // blz
                                                     account10Digits,                               // account10Digits
                                                     account10Digits[0]                             // accountType
                                                    );
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '76' again", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                if (!account10Digits.StartsWith("00"))
                {
                    throw new BankException("validation:3425", "algorithm is not applicable since sub account is missing but account hasn't been filled up with leading zeroes");
                }

                ValidateAccountInternalComputation76("76",                                          // algorithmId
                                                     account10Digits.Substring(3, 6).TrimStart(c0), // accountRelevantDigits
                                                     account10Digits[9].ToString(),                 // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,                        // weighting
                                                     11,                                            // checksumDivisor
                                                     null,                                          // checksumMapping
                                                     blz,                                           // blz
                                                     account10Digits,                               // account10Digits
                                                     account10Digits[2]                             // accountType
                                                    );
            }
        }

        // algorithm 77
        private void ValidateAccountAlgorithm77(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '77'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string strAccountRelevantDigits = account10Digits.Substring(5, 5);
            byte[] weighting = cWeighting_1_2_3_4_5;
            byte checksumDivisor = 11;

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            if (computedChecksum == 0)
            {
                traceManager.TraceLine(String.Format("Checksum:       OK (remainder of '{0}' at division by 11 equals to 0)", sum.ToString()), TraceManager.VerboseMode.VeryVerbose);
                return;
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '77' again", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                weighting = cWeighting_5_4_3_4_5;

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                sum = validationUtilities.AddAllValues(accountRelevantDigits);

                // compute check sum
                computedChecksum = (byte)(sum % checksumDivisor);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                if (computedChecksum == 0)
                {
                    traceManager.TraceLine(String.Format("Checksum:       OK (remainder of '{0}' at division by 11 equals to 0)", sum.ToString()), TraceManager.VerboseMode.VeryVerbose);
                    return;
                }
                else
                {
                    throw new BankException("validation:3426", String.Format("parity failure -> remainder of '{0}' at division by 11 equals to {1} <> 0", sum.ToString(), computedChecksum.ToString()));
                }
            }
        }

        // algorithm 78
        private void ValidateAccountAlgorithm78(string blz, string account10Digits)
        {
            if (account10Digits.StartsWith("00") && !account10Digits.StartsWith("000"))
            {
                throw new BankException("validation:3427", "algorithm is not applicable since account contains only 8 digits");
            }

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '78' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountAlgorithm00(blz, account10Digits);
        }

        // algorithm 79
        private void ValidateAccountAlgorithm79(string blz, string account10Digits)
        {
            if (account10Digits[0] == '3' ||
                account10Digits[0] == '4' ||
                account10Digits[0] == '5' ||
                account10Digits[0] == '6' ||
                account10Digits[0] == '7' ||
                account10Digits[0] == '8')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '79' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("79",                            // algorithmId
                                                     account10Digits.Substring(0, 9), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else if (account10Digits[0] == '1' || account10Digits[0] == '2' || account10Digits[0] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '79' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("79",                            // algorithmId
                                                     account10Digits.Substring(0, 8), // accountRelevantDigits
                                                     account10Digits[8].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else // if (account10Digits[0] == '0') 
            {
                throw new BankException("validation:3428", String.Format("algorithm is not applicable since first digit '{0}' of account is not 0", account10Digits[0]));
            }
        }

        // algorithm 80
        private void ValidateAccountAlgorithm80(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '80' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("80",                            // algorithmId
                                                     account10Digits.Substring(4, 5), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                if (account10Digits[2] == '9')
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '80' (by algorithm '51')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation51(blz, account10Digits);
                }
                else
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '80' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("80",                            // algorithmId
                                                         account10Digits.Substring(4, 5), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         7,                               // checksumDivisor
                                                         cChecksumMapping_7_0,            // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
            }
        }

        // algorithm 81
        private void ValidateAccountAlgorithm81(string blz, string account10Digits)
        {
            if (account10Digits[2] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '81' (by algorithm '51')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation51(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '81' (by algorithm '32')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm32(blz, account10Digits);
            }
        }

        // algorithm 82
        private void ValidateAccountAlgorithm82(string blz, string account10Digits)
        {
            if (account10Digits.Substring(2, 2).CompareTo("99") == 0)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '82' (by algorithm '10')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm10(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '82' (by algorithm '33')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm33(blz, account10Digits);
            }
        }

        // algorithm 83
        private void ValidateAccountAlgorithm83(string blz, string account10Digits)
        {
            try
            {
                // algorithm: customer account, method A
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '83' (method A by algorithm '32')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm32(blz, account10Digits);
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '83' (method B by algorithm '33')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm33(blz, account10Digits);
                }
                catch (BankException)
                {
                    if (account10Digits[9] == '7' || account10Digits[9] == '8' || account10Digits[9] == '9')
                    {
                        throw new BankException("validation:3429", String.Format("algorithm is not applicable since account failed in methods 1A / 1B and ends up with digit '{0}' (instead of 0,...,6)", account10Digits[9]));
                    }

                    try
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '83' (method C by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation06("83",                            // algorithmId
                                                             account10Digits.Substring(4, 5), // accountRelevantDigits
                                                             account10Digits[9].ToString(),   // givenChecksum
                                                             cWeighting_2_3_4_5_6,            // weighting
                                                             7,                               // checksumDivisor
                                                             cChecksumMapping_7_0,            // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                            );
                    }
                    catch (BankException)
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '83' (subject account by algorithm '33')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        // validate rules
                        if (account10Digits.Substring(2, 2).CompareTo("99") != 0)
                        {
                            throw new BankException("validation:3430", String.Format("algorithm is not applicable since digits 3 and 4 of account are '{0}' but not '99'", account10Digits.Substring(2, 2)));
                        }

                        string strAccountRelevantDigits = account10Digits.Substring(2, 7);
                        string strGivenChecksum = account10Digits[9].ToString();
                        byte[] weighting = cWeighting_2_3_4_5_6_7_8;
                        byte checksumDivisor = 11;

                        traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        // convert digits into array of bytes
                        byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
                        validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                        int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                        // compute check sum
                        byte computedChecksum = (byte)(sum % checksumDivisor);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        if (computedChecksum == 0) computedChecksum = 0;
                        else if (computedChecksum == 1) throw new BankException("validation:3431", String.Format("parity failure -> remainder of sum = '{0}' at division by 11 is '1'", sum.ToString()));
                        else computedChecksum = (byte)(checksumDivisor - computedChecksum);

                        traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        // compare computed checksum with given checksum
                        byte givenChecksum = byte.Parse(strGivenChecksum);
                        traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
                    }
                }
            }
        }

        // algorithm 84
        private void ValidateAccountAlgorithm84(string blz, string account10Digits)
        {
            try
            {
                // algorithm: customer account, method A
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '84' (method A by algorithm '33')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm33(blz, account10Digits);
            }
            catch (BankException)
            {
                if (account10Digits[2] == '9')
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '84' (method B by algorithm '51')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation51(blz, account10Digits);
                }
                else
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '84' (method B)", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    string strAccountRelevantDigits = account10Digits.Substring(4, 5);
                    string strGivenChecksum = account10Digits[9].ToString();
                    byte[] weighting = cWeighting_2_3_4_5_6;
                    byte checksumDivisor = 7;

                    traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    // convert digits into array of bytes
                    byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
                    validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                    int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                    // compute check sum
                    byte computedChecksum = (byte)(sum % checksumDivisor);
                    traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                    if (computedChecksum > 0) computedChecksum = (byte)(checksumDivisor - computedChecksum);
                    traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                    // compare computed checksum with given checksum
                    byte givenChecksum = byte.Parse(strGivenChecksum);
                    traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                    CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
                }
            }
        }

        // algorithm 85
        private void ValidateAccountAlgorithm85(string blz, string account10Digits)
        {
            try
            {
                // algorithm: method A
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '85' (method A by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("85",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '85' (method B by algorithm '33')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm33(blz, account10Digits);
                }
                catch (BankException)
                {
                    if (account10Digits[9] == '7' || account10Digits[9] == '8' || account10Digits[9] == '9')
                    {
                        throw new BankException("validation:3432", String.Format("algorithm is not applicable since account failed in methods 1A / 1B and ends up with digit '{0}' (instead of 0,...,6)", account10Digits[9]));
                    }

                    if (account10Digits.Substring(2, 2).CompareTo("99") == 0)
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '85' (method C by algorithm '02')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation02("85",                            // algorithmId
                                                             account10Digits.Substring(2, 7), // accountRelevantDigits
                                                             account10Digits[9].ToString(),   // givenChecksum
                                                             cWeighting_2_3_4_5_6_7_8,        // weighting
                                                             11,                              // checksumDivisor
                                                             cChecksumMapping_11_0,           // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                            );
                    }
                    else
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '85' (method C by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation06("85",                            // algorithmId
                                                             account10Digits.Substring(4, 5), // accountRelevantDigits
                                                             account10Digits[9].ToString(),   // givenChecksum
                                                             cWeighting_2_3_4_5_6,            // weighting
                                                             7,                               // checksumDivisor
                                                             cChecksumMapping_7_0,            // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                            );
                    }
                }
            }
        }

        // algorithm 86
        private void ValidateAccountAlgorithm86(string blz, string account10Digits)
        {
            try
            {
                // algorithm: method A
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '86' (method A by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("86",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                if (account10Digits[2] == '9')
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '85' (method B by algorithm '51')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation51(blz, account10Digits);
                }
                else
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '85' (method B by algorithm '32')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm32(blz, account10Digits);
                }
            }
        }

        // algorithm 87
        private void ValidateAccountAlgorithm87(string blz, string account10Digits)
        {
            // algorithm
            if (account10Digits[2] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '87' (by algorithm '51')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation51(blz, account10Digits);
            }
            else
            {
                try
                {
                    // algorithm A
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '87' (by algorithm 'A')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    int i, c2, d2, a5, p;
                    byte[] konto = validationUtilities.GetByteArrayOfString(account10Digits);

                    byte[] tab1 = { 0, 4, 3, 2, 6 };
                    byte[] tab2 = { 7, 1, 5, 9, 8 };

                    i = 4;

                    while (konto[i - 1] == 0) i++;

                    c2 = i % 2;
                    d2 = 0;
                    a5 = 0;

                    while (i < 10)
                    {
                        switch (konto[i - 1])
                        {
                            case 0: konto[i - 1] = 5; break;
                            case 1: konto[i - 1] = 6; break;
                            case 5: konto[i - 1] = 10; break;
                            case 6: konto[i - 1] = 1; break;
                        }

                        if (c2 == d2)
                        {
                            if (konto[i - 1] > 5)
                            {
                                if (c2 == 0 && d2 == 0)
                                {
                                    c2 = 1;
                                    d2 = 1;
                                    a5 = a5 + 6 - (konto[i - 1] - 6);
                                }
                                else
                                {
                                    c2 = 0;
                                    d2 = 0;
                                    a5 = a5 + konto[i - 1];
                                }
                            }
                            else
                            {
                                if (c2 == 0 && d2 == 0)
                                {
                                    c2 = 1;
                                    a5 = a5 + konto[i - 1];
                                }
                                else
                                {
                                    c2 = 0;
                                    a5 = a5 + konto[i - 1];
                                }
                            }
                        }
                        else
                        {
                            if (konto[i - 1] > 5)
                            {
                                if (c2 == 0)
                                {
                                    c2 = 1;
                                    d2 = 0;
                                    a5 = a5 - 6 + (konto[i - 1] - 6);
                                }
                                else
                                {
                                    c2 = 0;
                                    d2 = 1;
                                    a5 = a5 - konto[i - 1];
                                }
                            }
                            else
                            {
                                if (c2 == 0)
                                {
                                    c2 = 1;
                                    a5 = a5 - konto[i - 1];
                                }
                                else
                                {
                                    c2 = 0;
                                    a5 = a5 - konto[i - 1];
                                }
                            }
                        }

                        i++;
                    }

                    while (a5 < 0 || a5 > 4)
                    {
                        if (a5 > 4) a5 = a5 - 5;
                        else a5 = a5 + 5;
                    }

                    if (d2 == 0) p = tab1[a5];
                    else p = tab2[a5];

                    if (p == konto[10 - 1])
                    {
                        traceManager.TraceLine("Checksum:       OK", TraceManager.VerboseMode.VeryVerbose);
                        return;
                    }
                    else
                    {
                        if (konto[4 - 1] == 0)
                        {
                            if (p > 4) p = p - 5;
                            else p = p + 5;

                            if (p == konto[10 - 1])
                            {
                                traceManager.TraceLine("Checksum:       OK", TraceManager.VerboseMode.VeryVerbose);
                                return;
                            }
                        }
                    }

                    throw new BankException("validation:3433", "parity failure -> checksum is not ok");
                }
                catch (BankException)
                {
                    try
                    {
                        // algorithm B
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '87' (method B by algorithm '33')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountAlgorithm33(blz, account10Digits);
                    }
                    catch (BankException)
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '87' (method C)", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        string strAccountRelevantDigits = account10Digits.Substring(4, 5);
                        string strGivenChecksum = account10Digits[9].ToString();
                        byte[] weighting = cWeighting_2_3_4_5_6;
                        byte checksumDivisor = 7;

                        traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        // convert digits into array of bytes
                        byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
                        validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                        int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                        // compute check sum
                        byte computedChecksum = (byte)(sum % checksumDivisor);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        if (computedChecksum > 0) computedChecksum = (byte)(checksumDivisor - computedChecksum);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        // compare computed checksum with given checksum
                        byte givenChecksum = byte.Parse(strGivenChecksum);
                        traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
                    }
                }
            }
        }

        // algorithm 88
        private void ValidateAccountAlgorithm88(string blz, string account10Digits)
        {
            if (account10Digits[2] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '88' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("88",                            // algorithmId
                                                     account10Digits.Substring(2, 7), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7_8,        // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '88' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("88",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm 89
        private void ValidateAccountAlgorithm89(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '89'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);

            if (accountWithoutLeadingZeroes.Length <= 6 || accountWithoutLeadingZeroes.Length == 10)
            {
                traceManager.TraceLine(String.Format("Checksum:       OK (account consists of {0} digits)", accountWithoutLeadingZeroes.Length.ToString()), TraceManager.VerboseMode.Verbose);
                return;
            }
            else if (accountWithoutLeadingZeroes.Length == 8 || accountWithoutLeadingZeroes.Length == 9)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '89' (by algorithm '10')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm10(blz, account10Digits);
            }
            else if (accountWithoutLeadingZeroes.Length == 7)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '89' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("89",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else
            {
                throw new ChecksumException("argument:1410", String.Format("internal error -> invalid length of account '{0}'", accountWithoutLeadingZeroes));
            }
        }

        // algorithm 90
        private void ValidateAccountAlgorithm90(string blz, string account10Digits)
        {
            try
            {
                // algorithm: method A
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '90' (method A by algorithm '32')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm32(blz, account10Digits);
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '90' (method B by algorithm '33')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm33(blz, account10Digits);
                }
                catch (BankException)
                {
                    try
                    {
                        // validate rules
                        if (account10Digits[9] == '7' || account10Digits[9] == '8' || account10Digits[9] == '9')
                        {
                            throw new BankException("validation:3434", String.Format("algorithm is not applicable since account failed in methods 1A / 1B and ends up with digit '{0}' (instead of 0,...,6)", account10Digits[9]));
                        }

                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '90' (method C by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation06("90",                            // algorithmId
                                                             account10Digits.Substring(4, 5), // accountRelevantDigits
                                                             account10Digits[9].ToString(),   // givenChecksum
                                                             cWeighting_2_3_4_5_6,            // weighting
                                                             7,                               // checksumDivisor
                                                             cChecksumMapping_7_0,            // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                             );
                    }
                    catch (BankException)
                    {
                        try
                        {
                            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                            traceManager.TraceLine("trying algorithm '90' (method D by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                            ValidateAccountInternalComputation06("90",                            // algorithmId
                                                                 account10Digits.Substring(4, 5), // accountRelevantDigits
                                                                 account10Digits[9].ToString(),   // givenChecksum
                                                                 cWeighting_2_3_4_5_6,            // weighting
                                                                 9,                               // checksumDivisor
                                                                 cChecksumMapping_9_0,            // checksumMapping
                                                                 blz,                             // blz
                                                                 account10Digits                  // account10Digits
                                                                );
                        }
                        catch (BankException)
                        {
                            try
                            {
                                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                                traceManager.TraceLine("trying algorithm '90' (method E by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                                ValidateAccountInternalComputation06("90",                            // algorithmId
                                                                     account10Digits.Substring(4, 5), // accountRelevantDigits
                                                                     account10Digits[9].ToString(),   // givenChecksum
                                                                     cWeighting_2_1,                  // weighting
                                                                     10,                              // checksumDivisor
                                                                     cChecksumMapping_10_0,           // checksumMapping
                                                                     blz,                             // blz
                                                                     account10Digits                  // account10Digits
                                                                    );
                            }
                            catch (BankException)
                            {
                                // validate rules
                                if (account10Digits[2] != '9')
                                {
                                    throw new BankException("validation:3435", String.Format("algorithm is not applicable since digit 3 of account is '{0}' but not '9'", account10Digits[2]));
                                }

                                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                                traceManager.TraceLine("trying algorithm '90' (subject account by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                                ValidateAccountInternalComputation06("90",                            // algorithmId
                                                                     account10Digits.Substring(2, 7), // accountRelevantDigits
                                                                     account10Digits[9].ToString(),   // givenChecksum
                                                                     cWeighting_2_3_4_5_6_7_8,        // weighting
                                                                     11,                              // checksumDivisor
                                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                                     blz,                             // blz
                                                                     account10Digits                  // account10Digits
                                                                    );
                            }
                        }
                    }
                }
            }
        }

        // algorithm 91
        private void ValidateAccountAlgorithm91(string blz, string account10Digits)
        {
            try
            {
                // algorithm: method A
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '91' (method A by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("91",                            // algorithmId
                                                     account10Digits.Substring(0, 6), // accountRelevantDigits
                                                     account10Digits[6].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7,          // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                try
                {
                    // algorithm: method B
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '91' (method B by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("91",                            // algorithmId
                                                         account10Digits.Substring(0, 6), // accountRelevantDigits
                                                         account10Digits[6].ToString(),   // givenChecksum
                                                         cWeighting_7_6_5_4_3_2,          // weighting
                                                         11,                              // checksumDivisor
                                                         cChecksumMapping_10_0_11_0,      // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    try
                    {
                        // algorithm: method C
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '91' (method C by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation06("91",                             // algorithmId
                                                             account10Digits.Substring(0, 10), // accountRelevantDigits
                                                             account10Digits[6].ToString(),    // givenChecksum
                                                             cWeighting_2_3_4_0_5_6_7_8_9_A,   // weighting
                                                             11,                               // checksumDivisor
                                                             cChecksumMapping_10_0_11_0,       // checksumMapping
                                                             blz,                              // blz
                                                             account10Digits                   // account10Digits
                                                            );
                    }
                    catch (BankException)
                    {
                        // algorithm: method C
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm '91' (method D by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountInternalComputation06("91",                            // algorithmId
                                                             account10Digits.Substring(0, 6), // accountRelevantDigits
                                                             account10Digits[6].ToString(),   // givenChecksum
                                                             cWeighting_2_4_8_5_A_9,          // weighting
                                                             11,                              // checksumDivisor
                                                             cChecksumMapping_10_0_11_0,      // checksumMapping
                                                             blz,                             // blz
                                                             account10Digits                  // account10Digits
                                                            );
                    }
                }
            }
        }

        // algorithm 92
        private void ValidateAccountAlgorithm92(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '92' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation01("92",                            // algorithmId
                                                 account10Digits.Substring(3, 6), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_3_7_1,                // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 93
        private void ValidateAccountAlgorithm93(string blz, string account10Digits)
        {
            try
            {
                if (account10Digits.StartsWith("0000"))
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '93' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("93",                            // algorithmId
                                                         account10Digits.Substring(4, 5), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6,            // weighting
                                                         11,                              // checksumDivisor
                                                         cChecksumMapping_10_0_11_0,      // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                else
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '93' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("93",                            // algorithmId
                                                         account10Digits.Substring(0, 5), // accountRelevantDigits
                                                         account10Digits[5].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6,            // weighting
                                                         11,                              // checksumDivisor
                                                         cChecksumMapping_10_0_11_0,      // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
            }
            catch (BankException)
            {
                if (account10Digits.StartsWith("0000"))
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '93' again (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("93",                            // algorithmId
                                                         account10Digits.Substring(4, 5), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6,            // weighting
                                                         7,                               // checksumDivisor
                                                         cChecksumMapping_7_0,            // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                else
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '93' again (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("93",                            // algorithmId
                                                         account10Digits.Substring(0, 5), // accountRelevantDigits
                                                         account10Digits[5].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6,            // weighting
                                                         7,                               // checksumDivisor
                                                         cChecksumMapping_7_0,            // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
            }
        }

        // algorithm 94
        private void ValidateAccountAlgorithm94(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '94' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("94",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_1_2,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm 95
        private void ValidateAccountAlgorithm95(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '95' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            //  validate rules
            if ((account10Digits.CompareTo("0000000001") >= 0 && account10Digits.CompareTo("0001999999") <= 0) ||
                (account10Digits.CompareTo("0009000000") >= 0 && account10Digits.CompareTo("0025999999") <= 0) ||
                (account10Digits.CompareTo("0396000000") >= 0 && account10Digits.CompareTo("0499999999") <= 0) ||
                (account10Digits.CompareTo("0700000000") >= 0 && account10Digits.CompareTo("0799999999") <= 0))
            {
                traceManager.TraceLine("Checksum:       OK (account does not contain any checksum)", TraceManager.VerboseMode.VeryVerbose);
                return;
            }

            ValidateAccountAlgorithm06(blz, account10Digits);
        }

        // algorithm 96
        private void ValidateAccountAlgorithm96(string blz, string account10Digits)
        {
            try
            {
                // algorithm: method 1
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '96' (method 1 by algorithm '19')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm19(blz, account10Digits);
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '96' (method 2 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm00(blz, account10Digits);
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm '96' (method 3)", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    // validate rules
                    if (account10Digits.CompareTo("0001300000") >= 0 && account10Digits.CompareTo("0099399999") <= 0)
                    {
                        traceManager.TraceLine("Checksum:       OK (account lies in interval ['0001300000'..'0099399999'])", TraceManager.VerboseMode.VeryVerbose);
                    }
                    else
                    {
                        throw new BankException("validation:3436", "algorithm is not applicable since account is not contained in interval ['0001300000'..'0099399999']");
                    }
                }
            }
        }

        // algorithm 97
        private void ValidateAccountAlgorithm97(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '97')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // validate rules
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);
            string strGivenChecksum = account10Digits[9].ToString();

            if (accountWithoutLeadingZeroes.Length < 5)
            {
                throw new BankException("validation:3437", String.Format("algorithm is not applicable since account consists of only {0} digits", accountWithoutLeadingZeroes.Length.ToString()));
            }

            // algorithm
            string accountRelevantDigits = account10Digits.Substring(0, 9);
            uint account = UInt32.Parse(accountRelevantDigits);
            traceManager.TraceLine(String.Format("account:        {0}", account.ToString()), TraceManager.VerboseMode.VeryVerbose);
            uint div11 = account / 11;
            traceManager.TraceLine(String.Format("divide 11:      {0}", div11.ToString()), TraceManager.VerboseMode.VeryVerbose);
            uint mul11 = div11 * 11;
            traceManager.TraceLine(String.Format("mult. 11:       {0}", mul11.ToString()), TraceManager.VerboseMode.VeryVerbose);

            byte computedChecksum = (byte)(account - mul11);
            if (computedChecksum == 10) computedChecksum = 0;

            byte givenChecksum = byte.Parse(strGivenChecksum);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm 98
        private void ValidateAccountAlgorithm98(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '98' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation01("98",                            // algorithmId
                                                     account10Digits.Substring(2, 7), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_3_1_7,                // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm '98' (by algorithm '32')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm32(blz, account10Digits);
            }
        }

        // algorithm 99
        private void ValidateAccountAlgorithm99(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm '99' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            if (account10Digits.CompareTo("0396000000") >= 0 && account10Digits.CompareTo("0499999999") <= 0)
            {
                traceManager.TraceLine("Checksum:       --> OK (account is in interval 0396000000 ... 0499999999)", TraceManager.VerboseMode.VeryVerbose);
                return;
            }
            else
            {
                ValidateAccountAlgorithm06(blz, account10Digits);
            }
        }

        // algorithm A0
        private void ValidateAccountAlgorithmA0(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm 'A0'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            if (account10Digits.StartsWith("0000000"))
            {
                traceManager.TraceLine("Checksum:       --> OK (account has got only up to 3 digits and does not contain any checksum", TraceManager.VerboseMode.VeryVerbose);
                return;
            }
            else
            {
                string strAccountRelevantDigits = account10Digits.Substring(0, 9);
                string strGivenChecksum = account10Digits[9].ToString();
                byte[] weighting = cWeighting_2_4_8_5_A_0_0_0_0;
                byte checksumDivisor = 11;

                traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                // compute check sum
                byte computedChecksum = (byte)(sum % checksumDivisor);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                if (computedChecksum == 0) computedChecksum = 0;
                else if (computedChecksum == 1) computedChecksum = 0;
                else computedChecksum = (byte)(checksumDivisor - computedChecksum);

                traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
        }

        // algorithm A1
        private void ValidateAccountAlgorithmA1(string blz, string account10Digits)
        {
            // validate rules
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);

            if (accountWithoutLeadingZeroes.Length != 8 && accountWithoutLeadingZeroes.Length != 10)
            {
                throw new BankException("validation:3438", String.Format("algorithm is not applicable because account without leading zeroes '{0}' does not contain 8 or 10 digits", accountWithoutLeadingZeroes));
            }

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm 'A1' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            ValidateAccountInternalComputation00("A1",                            // algorithmId
                                                 account10Digits.Substring(0, 9), // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1_2_1_2_1_2_0_0,    // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm A2
        private void ValidateAccountAlgorithmA2(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A2' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A2' (by algorithm '04')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm04(blz, account10Digits);
            }
        }

        // algorithm A3
        private void ValidateAccountAlgorithmA3(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A3' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A3' (by algorithm '10')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm10(blz, account10Digits);
            }
        }

        // algorithm A4
        private void ValidateAccountAlgorithmA4(string blz, string account10Digits)
        {
            if (account10Digits.Substring(2, 2).CompareTo("99") == 0)
            {
                // only test for variants 3 and 4
                try
                {
                    // variant 3
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'A4' (variant 3 by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("A4",                            // algorithmId
                                                         account10Digits.Substring(4, 5), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6,            // weighting
                                                         11,                              // checksumDivisor
                                                         cChecksumMapping_10_0_11_0,      // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    // variant 4
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'A4' (variant 4 by algorithm '93')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm93(blz, account10Digits);
                }
            }
            else
            {
                try
                {
                    // variant 1
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'A4' (variant 1 by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("A4",                            // algorithmId
                                                         account10Digits.Substring(3, 6), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6_7,          // weighting
                                                         11,                              // checksumDivisor
                                                         cChecksumMapping_10_0_11_0,      // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    try
                    {
                        // variant 2
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm 'A4' (variant 2)", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        string strAccountRelevantDigits = account10Digits.Substring(3, 6);
                        string strGivenChecksum = account10Digits[9].ToString();
                        byte[] weighting = cWeighting_2_3_4_5_6_7;
                        byte checksumDivisor = 7;
                        Hashtable checksumMapping = cChecksumMapping_7_0;

                        traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        // convert digits into array of bytes
                        byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

                        // multiply digits with weighting array
                        validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                        int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                        // compute check sum
                        byte computedChecksum = (byte)(sum % checksumDivisor);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        computedChecksum = (byte)(checksumDivisor - computedChecksum);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        MapChecksum(checksumMapping, ref computedChecksum);
                        traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        // compare computed checksum with given checksum
                        byte givenChecksum = byte.Parse(strGivenChecksum);
                        traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
                    }
                    catch (BankException)
                    {
                        // variant 4
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm 'A4' again (by algorithm '93')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountAlgorithm93(blz, account10Digits);
                    }
                }
            }
        }

        // algorithm A5
        private void ValidateAccountAlgorithmA5(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A5' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                // validate rules
                if (account10Digits.StartsWith("9"))
                {
                    throw new BankException("validation:3439", String.Format("account '{0}' does not start with '9' and thus is invalid", account10Digits));
                }

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A5' (by algorithm '10')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm10(blz, account10Digits);
            }
        }

        // algorithm A6
        private void ValidateAccountAlgorithmA6(string blz, string account10Digits)
        {
            if (account10Digits.Substring(1, 1).CompareTo("8") == 0)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A6' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A6' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm01(blz, account10Digits);
            }
        }

        // algorithm A7
        private void ValidateAccountAlgorithmA7(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A7' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A7' (by algorithm '03')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm03(blz, account10Digits);
            }
        }

        // algorithm A8
        private void ValidateAccountAlgorithmA8(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A8' (by algorithm '81')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm81(blz, account10Digits);
            }
            catch (BankException)
            {
                // validate rules
                if (account10Digits[2] == '9')
                {
                    throw new BankException("validation:3440", String.Format("account '{0}' contains '9' at position 3 and thus is invalid", account10Digits));
                }

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A8' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation00("A8",                            // algorithmId
                                                     account10Digits.Substring(3, 6), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_1,                  // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
        }

        // algorithm A9
        private void ValidateAccountAlgorithmA9(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A9' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm01(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'A9' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm06(blz, account10Digits);
            }
        }

        // algorithm B0
        private void ValidateAccountAlgorithmB0(string blz, string account10Digits)
        {
            string accountWithoutLeadingZeroes = account10Digits.TrimStart('0');

            if (accountWithoutLeadingZeroes.Length < 10)
            {
                throw new BankException("validation:3441", String.Format("algorithm is not applicable since account '{0}' contains {1} digits (must contain 10 digits)", accountWithoutLeadingZeroes, accountWithoutLeadingZeroes.Length.ToString()));
            }

            if (account10Digits[0] == '8')
            {
                throw new BankException("validation:3442", String.Format("algorithm is not applicable since the first digit '{0}' of account '{1}' equals '8'", account10Digits[0], account10Digits));
            }

            if (account10Digits[7] == '1' ||
                account10Digits[7] == '2' ||
                account10Digits[7] == '3' ||
                account10Digits[7] == '6')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B0' (by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm09(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B0' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm06(blz, account10Digits);
            }
        }

        // algorithm B1
        private void ValidateAccountAlgorithmB1(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B1' (by algorithm '05')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm05(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B1' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm01(blz, account10Digits);
            }
        }

        // algorithm B2
        private void ValidateAccountAlgorithmB2(string blz, string account10Digits)
        {
            if ('0' <= account10Digits[0] && account10Digits[0] <= '7')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B2' (by algorithm '02')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm02(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B2' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
        }

        // algorithm B3
        private void ValidateAccountAlgorithmB3(string blz, string account10Digits)
        {
            if ('0' <= account10Digits[0] && account10Digits[0] <= '8')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B3' (by algorithm '32')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm32(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B3' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm06(blz, account10Digits);
            }
        }

        // algorithm B4
        private void ValidateAccountAlgorithmB4(string blz, string account10Digits)
        {
            if (account10Digits[0] == '9')
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B4' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B4' (by algorithm '02')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm02(blz, account10Digits);
            }
        }

        // algorithm B5
        private void ValidateAccountAlgorithmB5(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B5' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation01("B5",                            // algorithmId
                                                     account10Digits.Substring(0, 9), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_7_3_1,                // weighting
                                                     10,                              // checksumDivisor
                                                     cChecksumMapping_10_0,           // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B5' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                if (account10Digits[0] == '8' || account10Digits[0] == '9')
                {
                    throw new BankException("validation:3443", String.Format("algorithm is not applicable since the first digit '{0}' of account '{1}' equals '8' or '9'", account10Digits[0], account10Digits));
                }

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
        }

        // algorithm B6
        private void ValidateAccountAlgorithmB6(string blz, string account10Digits)
        {
            if (('1' <= account10Digits[0] && account10Digits[0] <= '9') ||
                (0 <= account10Digits.Substring(0, 5).CompareTo("02691") && account10Digits.Substring(0, 5).CompareTo("02699") <= 0))
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B6' (by algorithm '20')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm20(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B6' (by algorithm '53')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm53(blz, account10Digits);
            }
        }

        // algorithm B7
        private void ValidateAccountAlgorithmB7(string blz, string account10Digits)
        {
            if ((account10Digits.CompareTo("0001000000") >= 0) && (account10Digits.CompareTo("0005999999") <= 0))
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B7' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm01(blz, account10Digits);
            }

            if ((account10Digits.CompareTo("0700000000") >= 0) && (account10Digits.CompareTo("0899999999") <= 0))
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B7' (by algorithm '01')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm01(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B7' (by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm09(blz, account10Digits);
            }
        }

        // algorithm B8
        private void ValidateAccountAlgorithmB8(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B8' (by algorithm '20')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm20(blz, account10Digits);
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'B8' (by algorithm '29')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm29(blz, account10Digits);
                }
                catch (BankException)
                {
                    if ((0 <= account10Digits.Substring(0, 2).CompareTo("51") && account10Digits.Substring(0, 2).CompareTo("59") <= 0) ||
                        (0 <= account10Digits.Substring(0, 3).CompareTo("901") && account10Digits.Substring(0, 3).CompareTo("910") <= 0))
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm 'B8' (by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountAlgorithm09(blz, account10Digits);
                    }
                    else
                        throw new BankException("validation:3461", String.Format("algorithm is not applicable since the account number '{0}' does not start with two or three leading zeroes", account10Digits));
                }
            }
        }

        // algorithm B9
        private void ValidateAccountAlgorithmB9(string blz, string account10Digits)
        {
            if (account10Digits.StartsWith("00") && !account10Digits.StartsWith("000"))
            {
                // two leading zeroes: variant 1
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B9' (variant 1)", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                string strAccountRelevantDigits = account10Digits.Substring(2, 7);
                string strGivenChecksum = account10Digits[9].ToString();
                byte[] weighting = cWeighting_1_3_2;
                byte bytDigitDivisor = 11;
                byte checksumDivisor = 10;

                traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

                // multiply digits with weighting array
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                validationUtilities.AddWeightFromRightToLeft(accountRelevantDigits, weighting);

                int sum = validationUtilities.AddRemainders(accountRelevantDigits, bytDigitDivisor);

                // compute check sum
                byte computedChecksum = (byte)(sum % checksumDivisor);
                traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                if (computedChecksum != givenChecksum)
                {
                    computedChecksum += 5;
                    computedChecksum %= 10;
                }

                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
            else if (account10Digits.StartsWith("000") && !account10Digits.StartsWith("0000"))
            {
                // three leading zeroes: variant 2
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'B9' (variant 2)", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                string strAccountRelevantDigits = account10Digits.Substring(3, 6);
                string strGivenChecksum = account10Digits[9].ToString();
                byte[] weighting = cWeighting_1_2_3_4_5_6;
                byte bytSumDivisor = 11;

                traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

                // multiply digits with weighting array
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                // compute check sum
                byte computedChecksum = (byte)(sum % bytSumDivisor);
                traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                if (computedChecksum != givenChecksum)
                {
                    computedChecksum += 5;
                    computedChecksum %= 10;
                }

                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
            else
            {
                throw new BankException("validation:3444", String.Format("algorithm is not applicable since the account number '{0}' does not start with two or three leading zeroes", account10Digits));
            }
        }

        // algorithm C0
        private void ValidateAccountAlgorithmC0(string blz, string account10Digits)
        {
            if (account10Digits.StartsWith("00") && !account10Digits.StartsWith("000"))
            {
                // two leading zeroes: variant 1
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C0' (variant 1 by algorithm '52')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm52(blz, account10Digits);
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C0' (variant 1 by algorithm '20')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm20(blz, account10Digits);
                }
            }
            else
            {
                // more or less than two leading zeroes: variant 2

                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C0' (variant 2 by algorithm '20')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm20(blz, account10Digits);
            }
        }

        // algorithm C1
        private void ValidateAccountAlgorithmC1(string blz, string account10Digits)
        {
            if (!account10Digits.StartsWith("5"))
            {
                // does not start with "5": variant 1
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C1' (variant 1 by algorithm '17')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm17(blz, account10Digits);
            }
            else
            {
                // starts with "5": variant 2
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C1' (variant 2)", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // account parts
                string accountK = account10Digits.Substring(0, 1);   // account type digit
                string accountN = account10Digits.Substring(1, 8);   // continuous number
                string accountP = account10Digits.Substring(9, 1);   // checksum

                traceManager.TraceLine("account:        KNNNNNNNNP", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(String.Format("                {0}{1}{2}", accountK, accountN, accountP), TraceManager.VerboseMode.VeryVerbose);

                string strAccountRelevantDigits = account10Digits.Substring(0, 9);
                string strGivenChecksum = account10Digits[9].ToString();
                byte[] weighting = cWeighting_1_2;
                Hashtable checksumMapping = cChecksumMapping_11_0;

                traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

                // multiply digits with weighting array
                validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(accountRelevantDigits, weighting);
                validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
                int sum = validationUtilities.AddAllValues(accountRelevantDigits);
                sum -= 1;

                // compute check sum
                byte computedChecksum = (byte)(sum % 11);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                computedChecksum = (byte)(10 - computedChecksum);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                MapChecksum(checksumMapping, ref computedChecksum);
                traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
        }

        // algorithm C2
        private void ValidateAccountAlgorithmC2(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C2' (by algorithm '22')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm22(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C2' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
        }

        // algorithm C3
        private void ValidateAccountAlgorithmC3(string blz, string account10Digits)
        {
            if (account10Digits[0] == '9')
            {
                // variant 2
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C3' (variant 2 by algorithm '58')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm58(blz, account10Digits);
            }
            else
            {
                // variant 1
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C3' (variant 1 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
        }

        // algorithm C4
        private void ValidateAccountAlgorithmC4(string blz, string account10Digits)
        {
            if (account10Digits[0] == '9')
            {
                // variant 2
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C4' (variant 2 by algorithm '58')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm58(blz, account10Digits);
            }
            else
            {
                // variant 1
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C4' (variant 1 by algorithm '15')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm15(blz, account10Digits);
            }
        }

        // algorithm C5
        private void ValidateAccountAlgorithmC5(string blz, string account10Digits)
        {
            string accountWithoutLeadingZeroes = account10Digits.TrimStart(c0);

            if (accountWithoutLeadingZeroes.Length == 6)
            {
                char firstDigit = accountWithoutLeadingZeroes[0];

                if (('1' <= firstDigit) && (firstDigit <= '8'))
                {
                    // variant 1
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C5' (variant 1 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("75",                            // algorithmId
                                                         account10Digits.Substring(4, 5), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                         );
                }
                else
                {
                    throw new BankException("validation:3445", String.Format("algorithm is not applicable because the most left digit '{0}' is not between '1' and '8'", firstDigit));
                }
            }
            else if (accountWithoutLeadingZeroes.Length == 9)
            {
                char firstDigit = accountWithoutLeadingZeroes[0];

                if (('1' <= firstDigit) && (firstDigit <= '8'))
                {
                    // variant 1
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C5' (variant 1 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation00("75",                            // algorithmId
                                                         account10Digits.Substring(1, 5), // accountRelevantDigits
                                                         account10Digits[6].ToString(),   // givenChecksum
                                                         cWeighting_2_1,                  // weighting
                                                         10,                              // checksumDivisor
                                                         cChecksumMapping_10_0,           // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                else
                {
                    throw new BankException("validation:3446", String.Format("algorithm is not applicable because the most left digit '{0}' is not between '1' and '8'", firstDigit));
                }
            }
            else if (accountWithoutLeadingZeroes.Length == 10)
            {
                char firstDigit = accountWithoutLeadingZeroes[0];

                if ((firstDigit == '1') || (firstDigit == '4') || (firstDigit == '5') || (firstDigit == '6') || (firstDigit == '9'))
                {
                    // variant 2
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C5' (variant 2 by algorithm '29')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm29(blz, account10Digits);
                }
                else if (firstDigit == '3')
                {
                    // variant 3
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C5' (variant 3 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm00(blz, account10Digits);
                }
                else
                {
                    string firstTwoDigits = accountWithoutLeadingZeroes.Substring(0, 2);

                    if ((firstTwoDigits.CompareTo("70") == 0) || (firstTwoDigits.CompareTo("85") == 0))
                    {
                        // variant 4
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm 'C5' (variant 4 by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        ValidateAccountAlgorithm09(blz, account10Digits);
                    }
                    else
                    {
                        throw new BankException("validation:3447", String.Format("algorithm is not applicable because the most left digits '{0}' are not in [70..85]", firstTwoDigits));
                    }
                }
            }
            else if (accountWithoutLeadingZeroes.Length == 8)
            {
                char firstDigit = accountWithoutLeadingZeroes[0];

                if ((firstDigit == '3') || (firstDigit == '4') || (firstDigit == '5'))
                {
                    // variant 4
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C5' (variant 4 by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm09(blz, account10Digits);
                }
                else
                {
                    throw new BankException("validation:3448", String.Format("algorithm is not applicable because the most left digit '{0}' is not in (3,4,5)", firstDigit));
                }
            }
            else
            {
                throw new BankException("validation:3449", String.Format("algorithm is not applicable because the account '{0}' does not fit any variant conditions", accountWithoutLeadingZeroes));
            }
        }

        // algorithm C6
        private void ValidateAccountAlgorithmC6(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm 'C6'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            char firstDigit = account10Digits[0];

            if ((firstDigit == '4') || (firstDigit == '8'))
            {
                throw new BankException("validation:3456", String.Format("algorithm is not applicable because the most left digit '{0}' is not one of ('0..3', '5..7', '9')", firstDigit.ToString()));
            }

            // account10Digits[0] = 0|1|2|3|5|6|7|9
            string accountLeftPart;
            string accountRightPart = account10Digits.Substring(1, 8);

            if      (firstDigit == '0') accountLeftPart = "4451970";
            else if (firstDigit == '1') accountLeftPart = "4451981";
            else if (firstDigit == '2') accountLeftPart = "4451992";
            else if (firstDigit == '3') accountLeftPart = "4451993";
            else if (firstDigit == '5') accountLeftPart = "4344990";
            else if (firstDigit == '6') accountLeftPart = "4344991";
            else if (firstDigit == '7') accountLeftPart = "5499570";
            else if (firstDigit == '9') accountLeftPart = "5499579";
            else
            {
                throw new BankException("validation:3457", String.Format("algorithm is not applicable because the most left digit '{0}' is not one of ('0..3', '5..7', '9')", firstDigit));
            }

            string compositeAccount = accountLeftPart + accountRightPart;

            ValidateAccountInternalComputation00("C6",                            // algorithmId
                                                 compositeAccount,                // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm C7
        private void ValidateAccountAlgorithmC7(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C7' (by algorithm '63')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm63(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C7' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm06(blz, account10Digits);
            }
        }

        // algorithm C8
        private void ValidateAccountAlgorithmC8(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C8' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C8' (by algorithm '04')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm04(blz, account10Digits);
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'C8' (by algorithm '07')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm07(blz, account10Digits);
                }
            }
        }

        // algorithm C9
        private void ValidateAccountAlgorithmC9(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C9' (by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'C9' (by algorithm '07')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm07(blz, account10Digits);
            }
        }

        // algorithm D0
        private void ValidateAccountAlgorithmD0(string blz, string account10Digits)
        {
            if (!account10Digits.StartsWith("57"))
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D0' (variant 1 by algorithm '20')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm20(blz, account10Digits);
            }
            else
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D0' (variant 2 by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm09(blz, account10Digits);
            }
        }

        // algorithm D1
        private void ValidateAccountAlgorithmD1(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm 'D1'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            char firstDigit = account10Digits[0];

            if ((firstDigit == '7') || (firstDigit == '8'))
            {
                throw new BankException("validation:3458", String.Format("account '{0}' does not start with '0..6' or '9' and is thus invalid", account10Digits));
            }

            // firstDigit is one of ('0', '1', '2', '3', '4', '5', '6', '9')

            string accountLeftPart;
            string accountRightPart = account10Digits.Substring(1, 8);

            if      (firstDigit == '0') accountLeftPart = "4363380";
            else if (firstDigit == '1') accountLeftPart = "4363381";
            else if (firstDigit == '2') accountLeftPart = "4363382";
            else if (firstDigit == '3') accountLeftPart = "4363383";
            else if (firstDigit == '4') accountLeftPart = "4363384";
            else if (firstDigit == '5') accountLeftPart = "4363385";
            else if (firstDigit == '6') accountLeftPart = "4363386";
            else if (firstDigit == '9') accountLeftPart = "4363389";
            else
            {
                throw new BankException("validation:3457", String.Format("algorithm is not applicable because the most left digit '{0}' is not one of ('0..6' or '9')", firstDigit));
            }

            string compositeAccount = accountLeftPart + accountRightPart;

            ValidateAccountInternalComputation00("D1",                            // algorithmId
                                                 compositeAccount,                // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm D2
        private void ValidateAccountAlgorithmD2(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D2' (variant 1 by algorithm '95')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm95(blz, account10Digits);
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'D2' (variant 2 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm00(blz, account10Digits);
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'D2' (variant 3 by algorithm '68')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm68(blz, account10Digits);
                }
            }
        }

        // algorithm D3
        private void ValidateAccountAlgorithmD3(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D3' (variant 1 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D2' (variant 2 by algorithm '27')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm27(blz, account10Digits);
            }
        }

        // algorithm D4
        private void ValidateAccountAlgorithmD4(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm 'D4'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            char firstDigit = account10Digits[0];

            if (firstDigit == '0')
            {
                throw new BankException("validation:3463", String.Format("account '{0}' does not start with '1..9' and is thus invalid", account10Digits));
            }

            // firstDigit is one of ('1', '2', '3', '4', '5', '6', '7', '8', '9')

            string accountLeftPart = "428259";
            string accountRightPart = account10Digits.Substring(0, 9);
            string compositeAccount = accountLeftPart + accountRightPart;

            ValidateAccountInternalComputation00("D4",                            // algorithmId
                                                 compositeAccount,                // accountRelevantDigits
                                                 account10Digits[9].ToString(),   // givenChecksum
                                                 cWeighting_2_1,                  // weighting
                                                 10,                              // checksumDivisor
                                                 cChecksumMapping_10_0,           // checksumMapping
                                                 blz,                             // blz
                                                 account10Digits                  // account10Digits
                                                );
        }

        // algorithm D5
        private void ValidateAccountAlgorithmD5(string blz, string account10Digits)
        {
            if (account10Digits.Substring(2, 2).CompareTo("99") == 0)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D5' (by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountInternalComputation06("D5",                            // algorithmId
                                                     account10Digits.Substring(2, 7), // accountRelevantDigits
                                                     account10Digits[9].ToString(),   // givenChecksum
                                                     cWeighting_2_3_4_5_6_7_8_0_0,    // weighting
                                                     11,                              // checksumDivisor
                                                     cChecksumMapping_10_0_11_0,      // checksumMapping
                                                     blz,                             // blz
                                                     account10Digits                  // account10Digits
                                                    );
            }
            else
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'D5' (variant 2 by algorithm '06')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountInternalComputation06("D5",                            // algorithmId
                                                         account10Digits.Substring(3, 6), // accountRelevantDigits
                                                         account10Digits[9].ToString(),   // givenChecksum
                                                         cWeighting_2_3_4_5_6_7_0_0_0,    // weighting
                                                         11,                              // checksumDivisor
                                                         cChecksumMapping_10_0_11_0,      // checksumMapping
                                                         blz,                             // blz
                                                         account10Digits                  // account10Digits
                                                        );
                }
                catch (BankException)
                {
                    try
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm 'D5' (variant 3)", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        // convert digits into array of bytes
                        byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(account10Digits.Substring(3, 6));

                        validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, cWeighting_2_3_4_5_6_7_0_0_0);

                        // add all digits
                        int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                        // compute check sum
                        byte computedChecksum = (byte)(sum % 7);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        computedChecksum = (byte)(7 - computedChecksum);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        MapChecksum(cChecksumMapping_7_0, ref computedChecksum);
                        traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        // compare computed checksum with given checksum
                        byte givenChecksum = byte.Parse(account10Digits[9].ToString());
                        traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);                    
                    }
                    catch (BankException)
                    {
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine("trying algorithm 'D5' (variant 4)", TraceManager.VerboseMode.VeryVerbose);
                        traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                        // convert digits into array of bytes
                        byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(account10Digits.Substring(3, 6));

                        validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, cWeighting_2_3_4_5_6_7_0_0_0);

                        // add all digits
                        int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                        // compute check sum
                        byte computedChecksum = (byte)(sum % 10);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        computedChecksum = (byte)(10 - computedChecksum);
                        traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        MapChecksum(cChecksumMapping_10_0, ref computedChecksum);
                        traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                        // compare computed checksum with given checksum
                        byte givenChecksum = byte.Parse(account10Digits[9].ToString());
                        traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                        CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
                    }
                }
            }
        }        

        // algorithm D6
        private void ValidateAccountAlgorithmD6(string blz, string account10Digits)
        {
            try
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D6' (variant 1 by algorithm '07')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm07(blz, account10Digits);
            }
            catch (BankException)
            {
                try
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'D6' (variant 2 by algorithm '03')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm03(blz, account10Digits);
                }
                catch (BankException)
                {
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine("trying algorithm 'D6' (variant 3 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                    traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                    ValidateAccountAlgorithm00(blz, account10Digits);
                }
           }
        }

        // algorithm D7
        private void ValidateAccountAlgorithmD7(string blz, string account10Digits)
        {
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine("trying algorithm 'D7'", TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(account10Digits.Substring(0,9));

            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, cWeighting_2_1);
            validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);

            // add all digits
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % 10);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(account10Digits[9].ToString());
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // algorithm D8
        private void ValidateAccountAlgorithmD8(string blz, string account10Digits)
        {
            if (0 <= account10Digits.CompareTo("1000000000") && account10Digits.CompareTo("9999999999") <= 0)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D8' (variant 1 by algorithm '00')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm00(blz, account10Digits);
            }
            else if (0 <= account10Digits.CompareTo("0010000000") && account10Digits.CompareTo("0099999999") <= 0)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("trying algorithm 'D8' (variant 2 by algorithm '09')", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                ValidateAccountAlgorithm09(blz, account10Digits);
            }
            else
                throw new BankException("validation:3464", String.Format("algorithm is not applicable since the account number '{0}' is not in 1000000000..9999999999 nor in 0010000000..0099999999", account10Digits));
        }

        // helper function: maps checksum
        private void MapChecksum(Hashtable checksumMapping, ref byte computedChecksum)
        {
            if ((checksumMapping != null) && checksumMapping.ContainsKey(computedChecksum))
            {
                computedChecksum = (byte)checksumMapping[computedChecksum];
            }
        }

        // helper function: compares computed checksum with given checksum
        // throws exception if values are not identical
        private void CompareChecksums(byte computedChecksum, byte givenChecksum, string blz, string account10Digits)
        {
            traceManager.Trace(String.Format("Checksum:       {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVeryVerbose, true);
            if (computedChecksum == givenChecksum) traceManager.TraceLine(" --> OK", TraceManager.VerboseMode.VeryVeryVerbose, true);
            else traceManager.TraceLine(" --> ERROR", TraceManager.VerboseMode.VeryVeryVerbose, true);

            if (computedChecksum != givenChecksum)
            {
                throw new BankException("validation:3450", String.Format("parity failure -> computed checksum = '{0}' <> '{1}' = given checksum", computedChecksum.ToString(), givenChecksum.ToString()));
            }
        }

        // helper function
        private void ValidateAccountInternalComputation00(string algorithmId, string strAccountRelevantDigits, string strGivenChecksum, byte[] weighting, byte checksumDivisor, Hashtable checksumMapping, string blz, string account10Digits)
        {
            CheckInternalComputationAlgorithm(algorithmId, cCommonAlgorithms00);

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

            // multiply digits with weighting array
            if (algorithmId.CompareTo("30") == 0)
            {
                validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(accountRelevantDigits, weighting);
            }
            else
            {
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
            }

            // add all digits
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum;

            if (algorithmId.CompareTo("21") == 0)
            {

                // compute cross sum until there is only one digit left
                computedChecksum = validationUtilities.ComputeCrossSum(sum);

                int watchDog = 0;
                const int cWatchDogLimit = 10;

                while ((computedChecksum > 9) && (watchDog < cWatchDogLimit))
                {
                    computedChecksum = validationUtilities.ComputeCrossSum(computedChecksum);
                    watchDog++;
                }

                if (watchDog >= cWatchDogLimit)
                {
                    throw new BankException("validation:3451", String.Format("infinite loop -> account = '{0}', product sum = '{1}'", account10Digits, sum));
                }
            }
            else
            {
                computedChecksum = (byte)(sum % checksumDivisor);
            }

            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", strGivenChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // helper function
        private void ValidateAccountInternalComputation01(string algorithmId, string strAccountRelevantDigits, string strGivenChecksum, byte[] weighting, byte checksumDivisor, Hashtable checksumMapping, string blz, string account10Digits)
        {
            CheckInternalComputationAlgorithm(algorithmId, cCommonAlgorithms01);

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // helper function
        private void ValidateAccountInternalComputation02(string algorithmId, string strAccountRelevantDigits, string strGivenChecksum, byte[] weighting, byte checksumDivisor, Hashtable checksumMapping, string blz, string account10Digits)
        {
            CheckInternalComputationAlgorithm(algorithmId, cCommonAlgorithms02);

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // validation check
            if (computedChecksum > 9)
            {
                // checksum is two digits long, i.e. account is not valid
                throw new BankException("validation:3452", "algorithm is not applicable since checksum consists of two digits");
            }

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // helper function
        private void ValidateAccountInternalComputation06(string algorithmId, string strAccountRelevantDigits, string strGivenChecksum, byte[] weighting, byte checksumDivisor, Hashtable checksumMapping, string blz, string account10Digits)
        {
            CheckInternalComputationAlgorithm(algorithmId, cCommonAlgorithms06);

            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

            // multiply digits with weighting array
            if (algorithmId.CompareTo("64") == 0)
            {
                validationUtilities.MultiplyCyclicFromLeftToRightDigitByDigit(accountRelevantDigits, weighting);
            }
            else
            {
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            }

            if (algorithmId.CompareTo("89") == 0)
            {
                validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
            }

            // add all digits
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // consider special rule
            if ((algorithmId.CompareTo("16") == 0) && (computedChecksum == 1))
            {
                if (account10Digits[8] == account10Digits[9]) return; // account is valid
                else throw new BankException("validation:3453", String.Format("parity failure -> remainder = '1' but 9th and 10th digits are not the same ('{0}' <> '{1}')", account10Digits[8], account10Digits[9]));
            }

            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // helper function
        private void ValidateAccountInternalComputation51(string blz, string account10Digits)
        {
            try
            {
                // variant 1
                string strAccountRelevantDigits = account10Digits.Substring(2, 7);
                string strGivenChecksum = account10Digits[9].ToString();
                byte[] weighting = cWeighting_2_3_4_5_6_7_8;
                byte checksumDivisor = 11;
                Hashtable checksumMapping = cChecksumMapping_10_0_11_0;

                traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

                // multiply digits with weighting array
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                // compute check sum
                byte computedChecksum = (byte)(sum % checksumDivisor);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                computedChecksum = (byte)(checksumDivisor - computedChecksum);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                MapChecksum(checksumMapping, ref computedChecksum);
                traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
            catch (BankException)
            {
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine("variant 1 failed, trying again with variant 2", TraceManager.VerboseMode.VeryVerbose);
                traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

                // variant 2
                string strAccountRelevantDigits = account10Digits.Substring(0, 9);
                string strGivenChecksum = account10Digits[9].ToString();
                byte[] weighting = cWeighting_2_3_4_5_6_7_8_9_A;
                byte checksumDivisor = 11;
                Hashtable checksumMapping = cChecksumMapping_10_0_11_0;

                traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);

                // convert digits into array of bytes
                byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);

                // multiply digits with weighting array
                validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
                int sum = validationUtilities.AddAllValues(accountRelevantDigits);

                // compute check sum
                byte computedChecksum = (byte)(sum % checksumDivisor);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                computedChecksum = (byte)(checksumDivisor - computedChecksum);
                traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                MapChecksum(checksumMapping, ref computedChecksum);
                traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

                // compare computed checksum with given checksum
                byte givenChecksum = byte.Parse(strGivenChecksum);
                traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
                CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
            }
        }

        // helper function
        private void ValidateAccountInternalComputation63(string algorithmId, string strAccountRelevantDigits, string strGivenChecksum, byte[] weighting, byte checksumDivisor, Hashtable checksumMapping, string blz, string account10Digits)
        {
            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            validationUtilities.ComputeCrossSumForEachDigit(accountRelevantDigits);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte bytComputedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", bytComputedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            bytComputedChecksum = (byte)(checksumDivisor - bytComputedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", bytComputedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref bytComputedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", bytComputedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", bytComputedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(bytComputedChecksum, givenChecksum, blz, account10Digits);
        }

        // helper function
        private void ValidateAccountInternalComputation69(string algorithmId, string strAccountRelevantDigits, string strGivenChecksum, byte[] weighting, byte checksumDivisor, Hashtable checksumMapping, string blz, string account10Digits)
        {
            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // algorithm M10H (iterated transformation)

            // convert digits into array of bytes
            byte[] accountDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.TraceTemporaryResult(accountDigits);
            validationUtilities.TransformDigitByDigitFromRightToLeft(accountDigits, cTransformationMeh);
            validationUtilities.TraceTemporaryResult(accountDigits);
            int sum = validationUtilities.AddAllValues(accountDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            computedChecksum = (byte)(checksumDivisor - computedChecksum);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            MapChecksum(checksumMapping, ref computedChecksum);
            traceManager.TraceLine(String.Format("final checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // helper function
        private void ValidateAccountInternalComputation76(string algorithmId, string strAccountRelevantDigits, string strGivenChecksum, byte[] weighting, byte checksumDivisor, Hashtable checksumMapping, string blz, string account10Digits, char chrAccountType)
        {
            traceManager.TraceLine(String.Format("relevant:       {0}", strAccountRelevantDigits), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // validate rules
            if (chrAccountType != '0' &&
                chrAccountType != '4' &&
                chrAccountType != '6' &&
                chrAccountType != '7' &&
                chrAccountType != '8' &&
                chrAccountType != '9')
            {
                throw new BankException("validation:3454", String.Format("invalid account type '{0}' (must be either 0,4,6,7,8 or 9)", chrAccountType));
            }

            // convert digits into array of bytes
            byte[] accountRelevantDigits = validationUtilities.GetByteArrayOfString(strAccountRelevantDigits);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(accountRelevantDigits, weighting);
            int sum = validationUtilities.AddAllValues(accountRelevantDigits);

            // compute check sum
            byte computedChecksum = (byte)(sum % checksumDivisor);
            traceManager.TraceLine(String.Format("temp. checksum: {0}", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);

            if ((computedChecksum == 10) || (computedChecksum == 11))
            {
                traceManager.TraceLine(String.Format("Checksum:   OK (account cannot be validated since remainder '{0}' consists of not only one digit)", computedChecksum.ToString()), TraceManager.VerboseMode.VeryVerbose);
                return;
            }

            // compare computed checksum with given checksum
            byte givenChecksum = byte.Parse(strGivenChecksum);
            traceManager.TraceLine(String.Format("given checksum: ", computedChecksum.ToString().PadLeft(3)), TraceManager.VerboseMode.VeryVerbose);
            CompareChecksums(computedChecksum, givenChecksum, blz, account10Digits);
        }

        // helper: checks if algorithm may be used with aggregated algorithms
        private void CheckInternalComputationAlgorithm(string algorithmId, string commonlyUsedAlgorithms)
        {
            string prefixedAlgorithmId = "_" + algorithmId + "_";
            string prefixedCommonlyUsedAlgorithms = "_" + commonlyUsedAlgorithms + "_";

            if (prefixedCommonlyUsedAlgorithms.IndexOf(prefixedAlgorithmId) < 0)
            {
                throw new BankException("validation:3455", String.Format("algorithm '{0}' does not map to ValidateAccountInternalComputation<{1}>() method", algorithmId, commonlyUsedAlgorithms));
            }
        }

    }
}
