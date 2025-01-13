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
using System.Configuration;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;

using NUnit.Framework;

using ChecksumValidation;
using ChecksumValidation.BankAccountValidation;
using ChecksumValidation.CreditCardValidation;
using ChecksumValidation.IbanValidation;
using ChecksumValidation.IdentityValidation;

namespace ChecksumValidation.ChecksumUnitTest
{
    [TestFixture]
    public partial class ValidationTester
    {
        // constants
        private const string cDefaultBankDirectory = ".";
        private const string cDefaultTraceFile = "ChecksumValidation.UnitTest.log";
        private const string cDefaultVerboseMode = "None";

        // private members
        private TraceManager traceManager = null;
        private BankAccountValidator bankAccountValidator = null;
        private CreditCardValidator creditCardValidator = null;
        private IbanValidator ibanValidator = null;
        private IdentityValidator identityValidator = null;

        private FileStream fileStream = null;
        private TextWriter traceStream = null;

        // test data (positive tests)
        private Dictionary<string, string[]> validBankCodeAccountCombinations = new Dictionary<string, string[]>();
        private string validCreditCard = "4509472140549006";
        private string validIban = "DE60700517550000007229";
        private string validGermanIdentityCard = "2406055684D<<6810203<0705109<<<<<<6";
        private string validGermanPassport = "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<6";

        // test data (negative tests)
        private Dictionary<string, string[]> invalidBankCodeAccountCombinations = new Dictionary<string, string[]>();
        private string[] invalidCreditCardFormats = new string[] { "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890", "12345678901", "123456789012", "12345678901234567", "123456789012345678", "1234567890123456789", "12345678901234567890" }; // // invalid credit card formats (credit card number must have 13..16 characters)
        private Dictionary<string, string> invalidBankAccountFormats = new Dictionary<string, string>();
        private string[] invalidCreditCards = new string[] { "4509472140549000", "4509472140549001", "4509472140549002", "4509472140549003", "4509472140549004", "4509472140549005", "4509472140549007", "4509472140549008", "4509472140549009", "4509472140549010", "4509472140549011", "4509472140549012", "4509472140549013", "4509472140549015", "4509472140549016", "4509472140549017", "4509472140549018", "4509472140549019", "4509472140549020", "4509472140549021", "4509472140549023", "4509472140549024", "4509472140549025", "4509472140549026", "4509472140549027", "4509472140549028", "4509472140549031", "4509472140549032", "4509472140549033", "4509472140549034", "4509472140549035", "4509472140549036", "4509472140549037", "4509472140549038", "4509472140549039", "4509472140549040", "4509472140549041", "4509472140549042", "4509472140549043", "4509472140549044", "4509472140549045", "4509472140549046", "4509472140549047", "4509472140549049", "4509472140549050", "4509472140549051", "4509472140549052", "4509472140549053", "4509472140549054", "4509472140549056", "4509472140549057", "4509472140549058", "4509472140549059", "4509472140549060", "4509472140549061", "4509472140549062", "4509472140549064", "4509472140549065", "4509472140549066", "4509472140549067", "4509472140549068", "4509472140549069", "4509472140549070", "4509472140549072", "4509472140549073", "4509472140549074", "4509472140549075", "4509472140549076", "4509472140549077", "4509472140549078", "4509472140549079", "4509472140549080", "4509472140549081", "4509472140549082", "4509472140549083", "4509472140549084", "4509472140549085", "4509472140549086", "4509472140549087", "4509472140549088", "4509472140549090", "4509472140549091", "4509472140549092", "4509472140549093", "4509472140549094", "4509472140549095", "4509472140549096", "4509472140549098", "4509472140549099" };
        private string[] invalidIbanFormats = new string[] { "00", "00AB", "AB00", "00ABß", "00ABÜÖÄ", "GE0123456789ABCDEFG", "DE0123456780123456789XYZ" }; // // meet regular expression "^[A-Z]{2}[0-9]{2}[0-9A-Z]{1,30}$"
        private string[] invalidIbans = new string[] { "DE60700517550000007200", "DE60700517550000007201", "DE60700517550000007202", "DE60700517550000007203", "DE60700517550000007204", "DE60700517550000007205", "DE60700517550000007206", "DE60700517550000007207", "DE60700517550000007208", "DE60700517550000007209", "DE60700517550000007210", "DE60700517550000007211", "DE60700517550000007212", "DE60700517550000007213", "DE60700517550000007214", "DE60700517550000007215", "DE60700517550000007216", "DE60700517550000007217", "DE60700517550000007218", "DE60700517550000007219", "DE60700517550000007220", "DE60700517550000007221", "DE60700517550000007222", "DE60700517550000007223", "DE60700517550000007224", "DE60700517550000007225", "DE60700517550000007226", "DE60700517550000007227", "DE60700517550000007228", "DE60700517550000007230", "DE60700517550000007231", "DE60700517550000007232", "DE60700517550000007233", "DE60700517550000007234", "DE60700517550000007235", "DE60700517550000007236", "DE60700517550000007237", "DE60700517550000007238", "DE60700517550000007239", "DE60700517550000007240", "DE60700517550000007241", "DE60700517550000007242", "DE60700517550000007243", "DE60700517550000007244", "DE60700517550000007245", "DE60700517550000007246", "DE60700517550000007247", "DE60700517550000007248", "DE60700517550000007249", "DE60700517550000007250", "DE60700517550000007251", "DE60700517550000007252", "DE60700517550000007253", "DE60700517550000007254", "DE60700517550000007255", "DE60700517550000007256", "DE60700517550000007257", "DE60700517550000007258", "DE60700517550000007259", "DE60700517550000007260", "DE60700517550000007261", "DE60700517550000007262", "DE60700517550000007263", "DE60700517550000007264", "DE60700517550000007265", "DE60700517550000007266", "DE60700517550000007267", "DE60700517550000007268", "DE60700517550000007269", "DE60700517550000007270", "DE60700517550000007271", "DE60700517550000007272", "DE60700517550000007273", "DE60700517550000007274", "DE60700517550000007275", "DE60700517550000007276", "DE60700517550000007277", "DE60700517550000007278", "DE60700517550000007279", "DE60700517550000007280", "DE60700517550000007281", "DE60700517550000007282", "DE60700517550000007283", "DE60700517550000007284", "DE60700517550000007285", "DE60700517550000007286", "DE60700517550000007287", "DE60700517550000007288", "DE60700517550000007289", "DE60700517550000007290", "DE60700517550000007291", "DE60700517550000007292", "DE60700517550000007293", "DE60700517550000007294", "DE60700517550000007295", "DE60700517550000007296", "DE60700517550000007297", "DE60700517550000007298", "DE60700517550000007299" };
        private string[] invalidGermanIdentityCardFormats = new string[] { "abc", "1234123450x<<1234560<1234560<<<<<<0", "1234123450D<1234560<1234560<<<<<<0", "1234123450d<<12345601234560<<<<<<0", "1234123450D<<1234560<1234560<0", "1234123450d<<1234560<1234560<<<<<<<A" };
        private string[] invalidGermanPassportFormats = new string[] { "abc", "123412345x<<1234560M1234560<<<<<<<<<<<<<<<0", "123412345D<1234560F1234560<<<<<<<<<<<<<<<0", "123412345d<<1234560x1234560<<<<<<<<<<<<<<<0", "123412345D<<1234560m1234560<0", "123412345d<<1234560f1234560<<<<<<<<<<<<<<<A" };
        private string[] invalidGermanIdentityCards = new string[] { "2406055680D<<6810203<0705109<<<<<<6", "2406055681D<<6810203<0705109<<<<<<6", "2406055682D<<6810203<0705109<<<<<<6", "2406055683D<<6810203<0705109<<<<<<6", "2406055685D<<6810203<0705109<<<<<<6", "2406055686D<<6810203<0705109<<<<<<6", "2406055687D<<6810203<0705109<<<<<<6", "2406055688D<<6810203<0705109<<<<<<6", "2406055689D<<6810203<0705109<<<<<<6", "2406055684D<<6810200<0705109<<<<<<6", "2406055684D<<6810201<0705109<<<<<<6", "2406055684D<<6810202<0705109<<<<<<6", "2406055684D<<6810204<0705109<<<<<<6", "2406055684D<<6810205<0705109<<<<<<6", "2406055684D<<6810206<0705109<<<<<<6", "2406055684D<<6810207<0705109<<<<<<6", "2406055684D<<6810208<0705109<<<<<<6", "2406055684D<<6810209<0705109<<<<<<6", "2406055684D<<6810203<0705100<<<<<<6", "2406055684D<<6810203<0705101<<<<<<6", "2406055684D<<6810203<0705102<<<<<<6", "2406055684D<<6810203<0705103<<<<<<6", "2406055684D<<6810203<0705104<<<<<<6", "2406055684D<<6810203<0705105<<<<<<6", "2406055684D<<6810203<0705106<<<<<<6", "2406055684D<<6810203<0705107<<<<<<6", "2406055684D<<6810203<0705108<<<<<<6", "2406055684D<<6810203<0705109<<<<<<0", "2406055684D<<6810203<0705109<<<<<<1", "2406055684D<<6810203<0705109<<<<<<2", "2406055684D<<6810203<0705109<<<<<<3", "2406055684D<<6810203<0705109<<<<<<4", "2406055684D<<6810203<0705109<<<<<<5", "2406055684D<<6810203<0705109<<<<<<7", "2406055684D<<6810203<0705109<<<<<<8", "2406055684D<<6810203<0705109<<<<<<9" };
        private string[] invalidGermanPassports = new string[] { "2406055680D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055681D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055682D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055683D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055685D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055686D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055687D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055688D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055689D<<6810203M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810200M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810201M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810202M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810204M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810205M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810206M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810207M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810208M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810209M0705109<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705100<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705101<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705102<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705103<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705104<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705105<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705106<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705107<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705108<<<<<<<<<<<<<<<6", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<0", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<1", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<2", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<3", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<4", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<5", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<7", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<8", "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<9" };

        // ctor
        public ValidationTester()
        {
        }

        [TestFixtureSetUp]
        public void Init()
        {
            // bank directory
            string bankDirectory = ConfigurationManager.AppSettings["bank-directory"];
            if (String.IsNullOrEmpty(bankDirectory)) bankDirectory = cDefaultBankDirectory;

            // trace file
            string traceFile = ConfigurationManager.AppSettings["trace-file"];
            if (String.IsNullOrEmpty(traceFile)) traceFile = cDefaultTraceFile;

            // verbose mode
            string verboseMode = ConfigurationManager.AppSettings["verbose-mode"];
            if (String.IsNullOrEmpty(verboseMode)) verboseMode = cDefaultVerboseMode;

            TraceManager.VerboseMode verbose; 
                
            try
            {
                verbose = (TraceManager.VerboseMode)Enum.Parse(typeof(TraceManager.VerboseMode), verboseMode, true);
            }
            catch(ArgumentException)
            {
                throw new Exception(String.Format("invalid verbosity mode '{0}'", verboseMode));
            }

            // instance creation
            fileStream = File.Open(traceFile, FileMode.Create, FileAccess.Write);
            traceStream = new StreamWriter(fileStream);

            traceManager = new TraceManager(verbose, traceStream);

            bankAccountValidator = new BankAccountValidator(traceManager, bankDirectory);
            creditCardValidator = new CreditCardValidator(traceManager);
            ibanValidator = new IbanValidator(traceManager);
            identityValidator = new IdentityValidator(traceManager);

            // load bank directory
            bankAccountValidator.Load();

            // prepare random account number for arbitrary tests
            Random objRandom = new Random();
            double dblRandom = objRandom.NextDouble();    // 0.0 <= dblRandom < 1.0
            Int64 intRandom = (Int64)(dblRandom * 10000000000); // account consists of 10 digits
            string randomAccount = intRandom.ToString();

            // initialize table of valid bank code / bank account combinations
            AddBankCodeAccountCombination("00", new string[] { "9290701", "539290858", "1501824", "1501832" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("01", new string[] { "1234567899" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("02", new string[] { "1234567897" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("03", new string[] { "1234567890" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("04", new string[] { "1234567892" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("05", new string[] { "1234567897" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("06", new string[] { "94012341", "5073321010" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("07", new string[] { "0123456789" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("08", new string[] { "1234567897" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("09", new string[] { randomAccount }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("10", new string[] { "12345008", "87654008" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("11", new string[] { "1234567899" }, validBankCodeAccountCombinations);
            VerifyNoBlzForAlgorithmExists("12");
            AddBankCodeAccountCombination("13", new string[] { "0123456689" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("14", new string[] { "0123456781" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("15", new string[] { "0094012344" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("16", new string[] { "0123456793" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("17", new string[] { "0446786040" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("18", new string[] { "1234567899" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("19", new string[] { "0240334000", "0200520016" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("20", new string[] { "1234567896" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("21", new string[] { "0123456788" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("22", new string[] { "0123456784" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("23", new string[] { "1234560890" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("24", new string[] { "138301", "1306118605", "3307118608", "9307118603" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("25", new string[] { "521382181" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("26", new string[] { "0520309001", "1111118111", "0005501024" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("27", new string[] { "2847169488" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("28", new string[] { "19999000", "9130000201" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("29", new string[] { "3145863029" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("30", new string[] { "1234567892" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("31", new string[] { "1000000524", "1000000583" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("32", new string[] { "9141405", "1709107983", "0122116979", "0121114867", "9030101192", "9245500460" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("33", new string[] { "48658", "84956" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("34", new string[] { "9913000700", "9914001000" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("35", new string[] { "0000108443", "0000107451", "0000102921", "0000102349", "0000101709", "0000101599" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("36", new string[] { "113178", "146666" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("37", new string[] { "624315", "632500" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("38", new string[] { "191919", "1100660" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("39", new string[] { "200205", "10019400" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("40", new string[] { "1258345", "3231963" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("41", new string[] { "4013410024", "4016660195", "0166805317", "4019310079", "4019340829", "4019151002" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("42", new string[] { "59498", "59510" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("43", new string[] { "6135244", "9516893476" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("44", new string[] { "889006", "2618040504" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("45", new string[] { "3545343232", "4013410024", "0994681254", "0000012340", "1000199999", "0100114240" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("46", new string[] { "0235468612", "0837890901", "1041447600" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("47", new string[] { "1018000", "1003554450" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("48", new string[] { "1234567810" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("49", new string[] { "1234567897" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("50", new string[] { "4000005001", "4444442001" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("51", new string[] { "0001156071", "0001156136", "0000156078", "0000156071", "0199100002", "0099100010", "2599100002", "3199204090" }, validBankCodeAccountCombinations);
            if (bankAccountValidator.Banks["13051172"] != null) validBankCodeAccountCombinations.Add("13051172", new string[] { "42001500" }); // "52"
            AddBankCodeAccountCombination("53", new string[] { "382432256" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("54", new string[] { "4964137395", "4900010987" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("55", new string[] { "1234567895" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("56", new string[] { "0290545005", "9718304037" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("57", new string[] { "7777770000", "8888880000", "0185125434", "7500021766", "9400001734", "7800028282", "8100244186", "7777778800", "5001050352", "5045090090", "1909700805", "9322111030" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("58", new string[] { "1800881120", "9200654108", "1015222224", "3703169668" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("59", new string[] { "0", "1234567897" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("60", new string[] { "1234567891" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("61", new string[] { "2063099200", "0260760481" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("62", new string[] { "5029076701" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("63", new string[] { "123456600", "0001234566" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("64", new string[] { "1206473010", "5016511020" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("65", new string[] { "1234567400", "1234567590" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("66", new string[] { "100150502", "100154508", "101154508", "100154516", "101154516" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("67", new string[] { "1234567490" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("68", new string[] { "8889654328", "987654324", "987654328" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("69", new string[] { "1234567900", "1234567006" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("70", new string[] { "1928374650", "4567890" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("71", new string[] { "7101234007" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("72", new string[] { "4567893" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("73", new string[] { "0003503398", "0001340967", "0003503391", "0001340968", "0003503392", "0001340966", "123456", "199100002", "99100010", "2599100002", "199100004", "2599100003", "3199204090" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("74", new string[] { "1016", "26260", "242243", "242248", "18002113", "1821200043" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("75", new string[] { "123455" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("76", new string[] { "0012345600", "0000123456", "0006543200", "9012345600", "7876543100" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("77", new string[] { "10338", "13844", "65354", "69258" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("78", new string[] { "7581499", "9999999981" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("79", new string[] { "3230012688", "4230028872", "5440001898", "6330001063", "7000149349", "8000003577", "1550167850", "9011200140" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("80", new string[] { "340968", "340966", "199100002", "99100010", "2599100002", "199100004", "2599100003", "3199204090" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("81", new string[] { "0646440", "1359100", "199100002", "99100010", "2599100002", "199100004", "2599100003", "3199204090" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("82", new string[] { "123897", "3199500501" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("83", new string[] { "0001156071", "0001156136", "0000156078", "0000156071", "0099100002" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("84", new string[] { "100005", "393814", "950360", "199100002", "99100010", "2599100002", "199100004", "2599100003", "3199204090" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("85", new string[] { "0001156071", "0001156136", "0000156078", "0000156071", "3199100002" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("86", new string[] { "340968", "1001171", "1009588", "123897", "340960", "199100002", "99100010", "2599100002", "199100004", "2599100003", "3199204090" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("87", new string[] { "0000000406", "0000051768", "0010701590", "0010720185", "0000100005", "0000393814", "0000950360", "3199500501", "199100002", "99100010", "2599100002", "199100004", "2599100003", "3199204090" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("88", new string[] { "2525259", "1000500", "90013000", "92525253", "99913003" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("89", new string[] { "1098506", "32028008", "218433000" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("90", new string[] { "0001975641", "0001988654", "0000863530", "0000784451", "0000654321", "0000824491", "0000677747", "0000840507", "0000996663", "0000666034", "0099100002" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("91", new string[] { "2974118000", "5281741000", "9952810000", "2974117000", "5281770000", "9952812000", "8840019000", "8840050000", "8840087000", "8840045000", "8840012000", "8840055000", "8840080000" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("92", new string[] { "1234567893" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("93", new string[] { "6714790000", "0000671479", "1277830000", "0000127783", "1277910000", "0000127791", "3067540000", "0000306754" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("94", new string[] { "6782533003" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("95", new string[] { "0068007003", "0847321750", "6450060494", "6454000003" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("96", new string[] { "0000254100", "9421000009", "0000000208", "0101115152", "0301204301", "1312345" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("97", new string[] { "24010019" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("98", new string[] { "9619439213", "3009800016", "9619509976", "5989800173", "9619319999", "6719430018" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("99", new string[] { "0396000000", "0499999999", "0068007003", "0847321750" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A0", new string[] { "521003287", "54500", "3287", "18761", "28290" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A1", new string[] { "0010030005", "0010030997", "1010030054" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A2", new string[] { "3456789019", "5678901231", "6789012348", "3456789012" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A3", new string[] { "1234567897", "0123456782", "9876543210", "1234567890", "0123456789" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A4", new string[] { "0004711173", "0007093330", "0004711172", "0007093335", "1199503010", "8499421235", "0000862342", "8997710000", "0664040000", "0000905844", "5030101099", "0001123458", "1299503117" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A5", new string[] { "9941510001", "9961230019", "9380027210", "9932290910", "0000251437", "0007948344", "0000159590", "0000051640" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A6", new string[] { "800048548", "0855000014", "17", "55300030", "150178033", "600003555", "900291823" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A7", new string[] { "19010008", "19010438", "19010660", "19010876", "209010892" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A8", new string[] { "7436661", "7436670", "1359100", "7436660", "7436678", "0003503398", "0001340967" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A9", new string[] { "5043608", "86725", "504360", "822035", "32577083" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B0", new string[] { "1197423162", "1000000606", "1000000406", "1035791538" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B1", new string[] { "1434253150", "2746315471", "7414398260", "8347251693" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B2", new string[] { "0020012357", "0080012345", "0926801910", "1002345674", "8000990054", "9000481805" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B3", new string[] { "1000000060", "0000000140", "0000000019", "1002798417", "8409915001", "9635000101", "9730200100" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B4", new string[] { "9941510001", "9961230019", "9380027210", "9932290910", "0000251437", "0007948344", "000051640" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B5", new string[] { "0159006955", "2000123451", "1151043216", "9000939033", "0123456782", "0130098767", "1045000252" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B6", new string[] { "9110000000", "0269876545", "487310018" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B7", new string[] { "0700001529", "0730000019", "0001001008", "0001057887", "0001007222", "0810011825", "0800107653", "0005922372", "1234567890" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B8", new string[] { "0734192657", "6932875274", "3145863029", "2938692523", "5100000000", "5999999999", "9010000000", "9109999999" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B9", new string[] { "87920187", "41203755", "81069577", "61287958", "58467232", "7125633", "1253657", "4353631" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C0", new string[] { "0082335729", "0734192657", "6932875274" }, validBankCodeAccountCombinations);
            if (bankAccountValidator.Banks["13051172"] != null) validBankCodeAccountCombinations.Add("13051172", new string[] { "43001500", "48726458" });
            AddBankCodeAccountCombination("C1", new string[] { "0446786040", "0478046940", "0701625830", "0701625840", "0882095630", "5432112349", "5543223456", "5654334563", "5765445670", "5876556788" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C2", new string[] { "2394871426", "4218461950", "7352569148", "5127485166", "8738142564" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C3", new string[] { "9294182", "4431276", "19919", "9000420530", "9000010006", "9000577650" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C4", new string[] { "0000000019", "0000292932", "0000094455", "9000420530", "9000010006", "9000577650" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C5", new string[] { "0300020050", "0300566000", "1000061378", "1000061412", "4450164064", "4863476104", "5000000028", "5000000391", "6450008149", "6800001016", "9000100012", "9000210017", "3060188103", "3070402023", "0030000000", "0059999999", "7000000000", "7099999999", "8500000000", "8599999999" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C6", new string[] { "0000065516", "0203178249", "1031405209", "1082012201", "2003455189", "2004001016", "3110150986", "3068459207", "5035105948", "5286102149", "6028426119", "6861001755", "7008199027", "7002000023", "9000430223", "9000781153" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C7", new string[] { "3500022", "38150900", "600103660", "39101181", "94012341", "5073321010" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C8", new string[] { "3456789019", "5678901231", "3456789012", "0022007130", "0123456789", "0552071285" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C9", new string[] { "3456789019", "5678901231", "0123456789" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D0", new string[] { "6100272324", "6100273479", "5700000000", "5799999999" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D1", new string[] { "0082012203", "1452683581", "2129642505", "3002000027", "4230001407", "5000065514", "6001526215", "9000430223" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D2", new string[] { "189912137", "235308215", "4455667784", "1234567897", "51181008", "71214205" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D3", new string[] { "1600169591", "1600189151", "1800084079", "6019937007", "6021354007", "6030642006" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D4", new string[] { "1112048219", "2024601814", "3000005012", "4143406984", "5926485111", "6286304975", "7900256617", "8102228628", "9002364588" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D5", new string[] { "5999718138", "1799222116", "0099632004", "0004711173", "0007093330", "0000127787", "0004711172", "0007093335", "0000100062", "0000100088" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D6", new string[] { "3409", "585327", "1650513", "3601671056", "4402001046", "6100268241", "7001000681", "9000111105", "9001291005" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D7", new string[] { "0500018205", "0230103715", "0301000434", "0330035104", "0420001202", "0134637709", "0201005939", "0602006999" }, validBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D8", new string[] { "1403414848", "6800000439", "6899999954", "0010000000", "0099999999" }, validBankCodeAccountCombinations);

            // initialize table of invalid bank code / bank account combinations
            AddBankCodeAccountCombination("00", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("01", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("02", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("03", new string[] { "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("04", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("05", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("06", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("07", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("08", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("09", null, invalidBankCodeAccountCombinations); // // nothing to test, every bank account is valid
            AddBankCodeAccountCombination("10", new string[] { "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("11", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            VerifyNoBlzForAlgorithmExists("12");
            AddBankCodeAccountCombination("13", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("14", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("15", new string[] { "1234567890" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("16", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("17", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("18", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("19", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("20", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("21", new string[] { "1234567890", "1234567891", "1234567892", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("22", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("23", new string[] { "1234561890", "1234562890", "1234563890", "1234564890", "1234565890", "1234566890", "1234567890", "1234568890", "1234569890" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("24", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("25", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("26", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("27", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("28", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("29", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("30", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("31", new string[] { "1000000525", "1000000582" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("32", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("33", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("34", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("35", new string[] { "0000108440", "0000107459", "0000102922", "0000102348", "0000101703", "0000101594" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("36", new string[] { "113170", "146667" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("37", new string[] { "624312", "632501" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("38", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("39", new string[] { "200203", "10019405" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("40", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("41", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("42", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("43", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("44", new string[] { "1234567890", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("45", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("46", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("47", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("48", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("49", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("50", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("51", new string[] { "0099345678", "1234567890", "1234567891", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            if (bankAccountValidator.Banks["13051172"] != null) invalidBankCodeAccountCombinations.Add("13051172", new string[] { "40001500", "41001500", "43001500", "44001500", "45001500", "46001500", "47001500", "48001500", "49001500" }); // "52"
            AddBankCodeAccountCombination("53", new string[] { "380432256" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("54", new string[] { "4964137392", "4900010985" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("55", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("56", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("57", new string[] { "5302707782", "6412121212", "1813499124", "2206735010", "5123456780", "5123456782", "5123456784", "5123456785", "5123456786", "5123456787", "5123456788", "5123456789" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("58", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("59", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("60", new string[] { "1234567890", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("61", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("62", new string[] { "5029076501" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("63", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("64", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("65", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("66", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("67", new string[] { "1234567090", "1234567190", "1234567290", "1234567390", "1234567590", "1234567690", "1234567790", "1234567890", "1234567990" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("68", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("69", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("70", new string[] { "1928374659", "4567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("71", new string[] { "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("72", new string[] { "4567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("73", new string[] { "121212", "987654321", "1234567890", "1234567892", "1234567893", "1234567894", "1234567895", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("74", new string[] { "1011", "26265", "18002118", "6160000024" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("75", new string[] { "123459" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("76", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("77", new string[] { "10330", "13840", "65350", "69250" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("78", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("79", new string[] { "3230012680", "4230028870", "5440001890", "6330001060", "7000149340", "8000003570", "1550167859", "9011200149" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("80", new string[] { "1234567890", "1234567892", "1234567893", "1234567894", "1234567895", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("81", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("82", new string[] { "123890", "3199500500" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("83", new string[] { "0001156070", "0001156135" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("84", new string[] { "1234567890", "1234567891", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("85", new string[] { "1234567890", "1234567891", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("86", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("87", new string[] { "1234567890", "1234567891", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("88", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("89", new string[] { "1098500", "32028000", "218433009" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("90", new string[] { "0001924592", "0000901568", "0000820487", "0000726393", "0000924591", "0099100007", "1234567890", "1234567891", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("91", new string[] { "8840017000", "8840023000", "8840041000", "8840014000", "8840026000", "8840011000", "8840025000", "8840062000", "8840010000", "8840057000", "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("92", new string[] { "1234567890", "1234567891", "1234567892", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("93", new string[] { "6714790009", "0000671470", "1277830001", "0000127784", "1277910001", "0000127790", "3067540001", "0000306755" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("94", new string[] { "1234567890", "1234567891", "1234567892", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("95", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("96", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("97", new string[] { "24010010" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("98", new string[] { "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("99", new string[] { "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A0", new string[] { "521003280", "54501", "3280", "18760", "28299" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A1", new string[] { "0110030005", "0010030998", "0000030005", "1234567890", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A2", new string[] { "1234567890", "1234567890", "0123456789", "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A3", new string[] { "6543217890", "0543216789", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A4", new string[] { "6099702031", "0000399443", "0000553313" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A5", new string[] { "9941510002", "9961230020", "0000251438", "0007948345", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A6", new string[] { "860000817", "810033652", "305888", "200071280", "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A7", new string[] { "209010893", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A8", new string[] { "0003503391", "0001340966", "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("A9", new string[] { "86724", "292497", "30767208", "1234567890", "1234567891", "1234567893", "1234567894", "1234567895", "1234567896", "1234567897", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B0", new string[] { "8137423260", "600000606", "51234309", "1000000405", "1035791539", "8035791532", "535791830", "51234901" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B1", new string[] { "0123456789", "2345678901", "0123456789", "2345678901", "5678901236", "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B2", new string[] { "0020012399", "0080012347", "0080012370", "0932100027", "3310123454", "8000990057", "8011000126", "9000481800", "9980480111", "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B3", new string[] { "9635100101", "9730300100", "1234567890", "1234567891", "1234567892", "1234567893", "1234567894", "1234567895", "1234567896", "1234567898", "1234567899" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B4", new string[] { "9941510002", "9961230020", "0000251438", "0007948345", "0000159590" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B5", new string[] { "7414398260", "8347251693", "2345678901", "5678901234", "9000293707", "0159004165", "0023456787", "0056789018", "3045000333" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B6", new string[] { "9111000000", "0269456780", "467310018", "477310018" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B7", new string[] { "0001057886", "0003815570", "0005620516", "0740912243", "0893524479" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B8", new string[] { "0132572975", "4932198769", "9000873333", "5011654369", "9000412340", "9310305011", "0132572975", "9170873333", "9000412340", "9310305011", "5099999999", "6000000000", "9000000000", "9110000009" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("B9", new string[] { "88034023", "43025432", "86521362", "61256523", "54352684", "2356412", "5435886", "9435414" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C0", new string[] { "0132572975", "3038752371" }, invalidBankCodeAccountCombinations);
            if (bankAccountValidator.Banks["13051172"] != null) invalidBankCodeAccountCombinations.Add("13051172", new string[] { "82335729", "29837521" });
            AddBankCodeAccountCombination("C1", new string[] { "0446786240", "0478046340", "0701625730", "0701625440", "0882095130", "5432112341", "5543223458", "5654334565", "5765445672", "5876556780" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C2", new string[] { "0328705282", "9024675131", "0328705282", "9024675131" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C3", new string[] { "17002", "123451", "122448", "9000734028", "9000733227", "9000731120" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C4", new string[] { "0000000017", "0000292933", "0000094459", "9000726558", "9001733457", "9000732000" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C5", new string[] { "0000302589", "0000507336", "0302555000", "0302589000", "1000061457", "1000061498", "4864446015", "4865038012", "5000001028", "5000001075", "6450008150", "6542812818", "9000110012", "9000300310", "3081000783", "3081308871", "0012345678", "0023456789", "0067890123", "0078901234", "0089012345", "0090123456", "1234567890", "2345678901", "3456789012", "4567890123", "5678901235", "6789012345", "7123456789", "7234567890", "7345678901", "7456789012", "7567890123", "7678901234", "7789012345", "7890123456", "7901234567", "8012345678", "8123456789", "8234567890", "8345678901", "8456789012", "8678901234", "8789012344", "8890123456", "8901234567", "9012345678" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C6", new string[] { "0525111212", "0091423614", "1082311275", "1000118821", "2004306518", "2016001206", "3462816371", "3622548632", "4232300145", "4000456126", "5002684526", "5564123850", "6295473774", "6640806317", "7000062022", "7006003027", "8348300005", "8654216984", "9000641509", "9000260986" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C7", new string[] { "1234517892", "987614325" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C8", new string[] { "1234567890", "9012345678" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("C9", new string[] { "3456789012", "1234567890", "9012345678" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D0", new string[] { "6100272885", "6100273377", "6100274012", "5699999999", "5800000000" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D1", new string[] { "0000260986", "1062813622", "2256412314", "3012084101", "4006003027", "5814500990", "6128462594", "7000062025", "8003306026", "9000641509" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D2", new string[] { "6414241", "179751314" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D3", new string[] { "1600166307", "6025017009", "6028267003", "6019835001" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D4", new string[] { "0359432843", "1000062023", "2204271250", "3051681017", "4000123456", "5212744564", "6286420010", "7859103459", "8003306026", "9916524534" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D5", new string[] { "3299632008", "1999204293", "0399242139", "0004711179", "8623420004", "0001123458", "8623410009", "0001123458", "0000100084", "0000100085" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D6", new string[] { "33394", "595795", "16400501", "3615071237", "6039267013", "6039316014", "7004017653", "9002720007", "9017483524" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D7", new string[] { "0501006102", "0231307867", "0301005331", "0330034104", "0420001302", "0135638809", "0202005939", "0601006977" }, invalidBankCodeAccountCombinations);
            AddBankCodeAccountCombination("D8", new string[] { "3012084101", "1062813622", "0000260986" }, invalidBankCodeAccountCombinations);

            // invalid bank account formats
            invalidBankAccountFormats.Add("1a2", "b3d"); // blz and account have characters
            invalidBankAccountFormats.Add("1", "1234567890"); // blz has less than 8 digits
            invalidBankAccountFormats.Add("123456789", "1234567890"); // blz has more than 8 digits
            invalidBankAccountFormats.Add("12345678", "12345678901"); // account has more than 10 digits
        }

        private void AddBankCodeAccountCombination(string checksumCode, string[] validAccounts, Dictionary<string, string[]> validBankCodeAccountCombinations)
        {
            string bankCode = ValidationUtilities.FindFirstBankCodeByChecksumCode(checksumCode, bankAccountValidator);
            if ((bankCode != null) && (bankCode.Length > 0)) validBankCodeAccountCombinations.Add(bankCode, validAccounts);
        }

        [TestFixtureTearDown]
        public void Dispose()
        {
            if (traceStream != null) traceStream.Close();
            if (fileStream != null) fileStream.Close();

            bankAccountValidator = null;
            creditCardValidator = null;
            ibanValidator = null;
            identityValidator = null;
            traceManager = null;
        }

        // 
        // NUnit: BankAccountValidation
        // 

        [Test]
        [Category("BankAccountValidation")]
        [ExpectedException(typeof(NullReferenceException))]
        public void TestBankAccountValidationNegativelyNullReferenceException()
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);

            try
            {
                NullReferenceExceptionTestForBankAccountValidation(null, null);
                NullReferenceExceptionTestForBankAccountValidation(null, String.Empty);
                NullReferenceExceptionTestForBankAccountValidation(String.Empty, null);
                NullReferenceExceptionTestForBankAccountValidation(null, String.Empty);

                throw new NullReferenceException("TestBankAccountValidationNegativelyNullReferenceException() ran successfully");
            }
            catch (NullReferenceException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("BankAccountValidation")]
        public void TestBankAccountValidationNegativelyArgumentException()
        {
            try
            {
                foreach (string bankCode in invalidBankAccountFormats.Keys)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);

                    string account = invalidBankAccountFormats[bankCode];
                    ArgumentExceptionTestForBankAccountValidation(bankCode, account);
                }
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("BankAccountValidation")]
        public void TestBankAccountValidationPositively()
        {
            if ((validBankCodeAccountCombinations == null) || (validBankCodeAccountCombinations.Count == 0)) throw new ArgumentNullException("valid bank codes / bank accounts not initialized!");

            foreach (string bankCode in validBankCodeAccountCombinations.Keys)
            {
                string[] bankAccounts = validBankCodeAccountCombinations[bankCode];

                if (bankAccounts != null)
                {
                    foreach (string bankAccount in bankAccounts)
                    {
                        traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                        bankAccountValidator.Validate(bankCode, bankAccount);
                    }
                }
            }
        }

        [Test]
        [Category("BankAccountValidation")]
        [ExpectedException(typeof(BankException))]
        public void TestBankAccountValidationNegativelyBankException()
        {
            if ((invalidBankCodeAccountCombinations == null) || (invalidBankCodeAccountCombinations.Count == 0)) throw new ArgumentNullException("invalid bank codes / bank accounts not initialized!");

            try
            {
                foreach (string bankCode in invalidBankCodeAccountCombinations.Keys)
                {
                    string[] bankAccounts = invalidBankCodeAccountCombinations[bankCode];

                    if (bankAccounts != null)
                    {
                        foreach (string bankAccount in bankAccounts)
                        {
                            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                            InvalidBlzAccountCombinationTest(bankCode, bankAccount);
                        }
                    }
                }

                // finished
                throw new BankException("test:0000", "negative tests finished successfully");
            }
            catch (BankException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }

        }

        // 
        // NUnit: CreditCardValidation
        // 

        [Test]
        [Category("CreditCardValidation")]
        [ExpectedException(typeof(NullReferenceException))]
        public void TestCreditCardValidationNegativelyNullReferenceException()
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);

            try
            {
                NullReferenceExceptionTestForCreditCardValidation(null);
                NullReferenceExceptionTestForCreditCardValidation(String.Empty);

                throw new NullReferenceException("TestCreditCardValidationNegativelyNullReferenceException() ran successfully");
            }
            catch (NullReferenceException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("CreditCardValidation")]
        [ExpectedException(typeof(ArgumentException))]
        public void TestCreditCardValidationNegativelyArgumentException()
        {
            try
            {
                foreach (string invalidCreditCard in invalidCreditCardFormats)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    ArgumentExceptionTestForCreditCardValidation(invalidCreditCard);
                }

                throw new ArgumentException("TestCreditCardValidationNegativelyArgumentException() ran successfully");
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("CreditCardValidation")]
        public void TestCreditCardValidationPositively()
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
            creditCardValidator.Validate(validCreditCard);
        }

        [Test]
        [Category("CreditCardValidation")]
        [ExpectedException(typeof(CreditCardValidationException))]
        public void TestCreditCardValidationNegativelyCreditCardValidationException()
        {
            try
            {
                foreach (string creditCard in invalidCreditCards)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    InvalidCreditCardTest(creditCard);
                }

                // finished
                throw new CreditCardValidationException("test:0001", "negative tests finished successfully", "dummy");
            }
            catch (CreditCardValidationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        //
        // NUnit: IbanValidation
        //

        [Test]
        [Category("IbanValidation")]
        [ExpectedException(typeof(NullReferenceException))]
        public void TestIbanValidationNegativelyNullReferenceException()
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);

            try
            {
                NullReferenceExceptionTestForIbanValidation(null);
                NullReferenceExceptionTestForIbanValidation(String.Empty);

                throw new NullReferenceException("TestIbanValidationNegativelyNullReferenceException() ran successfully");
            }
            catch(NullReferenceException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("IbanValidation")]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIbanValidationNegativelyArgumentException()
        {
            try
            {
                foreach (string iban in invalidIbanFormats)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    ArgumentExceptionTestForIbanValidation(iban);
                }

                throw new ArgumentException("TestIbanValidationNegativelyArgumentException() ran successfully");
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("IbanValidation")]
        public void TestIbanValidatorPositively()
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
            ibanValidator.Validate(validIban);
        }

        [Test]
        [Category("IbanValidation")]
        [ExpectedException(typeof(IbanValidationException))]
        public void TestIbanValidationNegativelyIbanValidationException()
        {
            try
            {
                foreach (string iban in invalidIbans)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    InvalidIbanTest(iban);
                }

                // finished
                throw new IbanValidationException("test:0002", "negative tests finished successfully", "dummy");
            }
            catch (IbanValidationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }

        }

        // 
        // NUnit: IdentityValidation
        //

        [Test]
        [Category("IdentityValidation")]
        [ExpectedException(typeof(NullReferenceException))]
        public void TestIdentityValidationNegativelyNullReferenceException()
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);

            try
            {
                NullReferenceExceptionTest(null, null);
                NullReferenceExceptionTest(null, String.Empty);
                NullReferenceExceptionTest(String.Empty, null);
                NullReferenceExceptionTest(String.Empty, String.Empty);

                throw new NullReferenceException("TestIdentityValidationNegativelyNullReferenceException() ran successfully");
            }
            catch (NullReferenceException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("IdentityValidation")]
        [ExpectedException(typeof(ArgumentException))]
        public void TestIdentityValidationNegativelyArgumentException()
        {
            try
            {
                traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                ArgumentExceptionTestForIdentityValidation("invalid-personal-identity-type", "dummy");  // invalid identity type

                foreach (string identityCard in invalidGermanIdentityCardFormats)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    ArgumentExceptionTestForIdentityValidation("GermanIdentityCard", identityCard);                                   
                }

                foreach (string passport in invalidGermanPassportFormats)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    ArgumentExceptionTestForIdentityValidation("GermanPassport", passport);                                    
                }

                throw new ArgumentException("TestIdentityValidationNegativelyArgumentException() ran successfully");
            }
            catch (ArgumentException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

        [Test]
        [Category("IdentityValidation")]
        public void TestIdentityValidationPositively()
        {
            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
            identityValidator.Validate("GermanIdentityCard", validGermanIdentityCard);

            traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
            identityValidator.Validate("GermanPassport", validGermanPassport);
        }

        [Test]
        [Category("IdentityValidation")]
        [ExpectedException(typeof(IdentityValidationException))]
        public void TestIdentityValidationNegativelyIdentityValidationException()
        {
            try
            {
                foreach (string identityCard in invalidGermanIdentityCards)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    InvalidPersonalIdentityTest("GermanIdentityCard", identityCard);
                }

                foreach (string passport in invalidGermanPassports)
                {
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.VeryVerbose);
                    InvalidPersonalIdentityTest("GermanPassport", passport);
                }

                // finished
                throw new IdentityValidationException("test:0003", "negative tests finished successfully", "dummy", "dummy");
            }
            catch (IdentityValidationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.ToString());
            }
        }

    }
}
