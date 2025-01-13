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

namespace ChecksumValidation.CreditCardValidation
{
    public sealed class CreditCardValidator
    {
        // strong typing of supported credit card types
        internal enum CreditCardInstitute : byte
        {
            AmericanExpress,
            DinersClub,
            Discover,
            EnRoute,
            JCB,
            MasterCard,
            Visa,
            Bahncard,
            MilesAndMore
        }

        // private helper class to hold information about credit card type
        internal sealed class CreditCardInfo
        {
            internal CreditCardInstitute creditCardInstitute;
            internal string strCreditCardInstitute;
            internal byte length;
            internal string[] prefixes;
            internal bool considerPrefixForValidation;

            // ctor
            internal CreditCardInfo(CreditCardInstitute creditCardInstitute, string strCreditCardInstitute, byte length, string[] prefixes, bool considerPrefixForValidation)
            {
                this.creditCardInstitute = creditCardInstitute;
                this.strCreditCardInstitute = strCreditCardInstitute;
                this.length = length;
                this.prefixes = prefixes;
                this.considerPrefixForValidation = considerPrefixForValidation;
            }
        }

        // private members
        private Hashtable creditCards;
        private TraceManager traceManager;
        private ValidationUtilities validationUtilities;

        // ctor
        public CreditCardValidator(TraceManager traceManager)
        {
            this.traceManager = traceManager;
            this.validationUtilities = new ValidationUtilities(traceManager);

            creditCards = new Hashtable(Enum.GetValues(CreditCardInstitute.AmericanExpress.GetType()).Length);

            // initialization of credit card information
            creditCards.Add(CreditCardInstitute.AmericanExpress, new CreditCardInfo(CreditCardInstitute.AmericanExpress, "American Express", 15, new string[] { "34", "37" }, true));
            creditCards.Add(CreditCardInstitute.DinersClub, new CreditCardInfo(CreditCardInstitute.DinersClub, "Diner's Club", 14, new string[] { "300", "301", "302", "303", "304", "305", "36", "38" }, true));
            creditCards.Add(CreditCardInstitute.Discover, new CreditCardInfo(CreditCardInstitute.Discover, "Discover", 16, new string[] { "6011" }, false));
            creditCards.Add(CreditCardInstitute.EnRoute, new CreditCardInfo(CreditCardInstitute.EnRoute, "EnRoute", 15, new string[] { "2014", "2149" }, true));
            creditCards.Add(CreditCardInstitute.JCB, new CreditCardInfo(CreditCardInstitute.JCB, "JCB", 16, new string[] { "2131", "1800", "3088" }, true));
            creditCards.Add(CreditCardInstitute.MasterCard, new CreditCardInfo(CreditCardInstitute.MasterCard, "MasterCard", 16, new string[] { "51", "52", "53", "54", "55" }, true));
            creditCards.Add(CreditCardInstitute.Visa, new CreditCardInfo(CreditCardInstitute.Visa, "Visa", 16, new string[] { "4" }, true));
            creditCards.Add(CreditCardInstitute.Bahncard, new CreditCardInfo(CreditCardInstitute.Bahncard, "BahnCard", 16, new string[] { "70" }, true));
            creditCards.Add(CreditCardInstitute.MilesAndMore, new CreditCardInfo(CreditCardInstitute.MilesAndMore, "Miles & More", 15, new string[] { "99" }, true));
        }

        // checks credit card type for given credit card number
        public string GetCreditCardType(string creditCardNumber)
        {
            if (String.IsNullOrEmpty(creditCardNumber)) throw new ChecksumException("argument:1304", "credit card number must not be empty");

            ValidateRegExCreditCardNumber(creditCardNumber);
            ValidateCreditCardNumberLength(creditCardNumber);

            foreach (Object key in creditCards.Keys)
            {
                CreditCardInstitute creditCardInstitute = (CreditCardInstitute)key;
                CreditCardInfo creditCardInfo = (CreditCardInfo)(creditCards[creditCardInstitute]);

                string[] prefixes = creditCardInfo.prefixes;

                foreach (string prefix in prefixes)
                {
                    if (creditCardNumber.StartsWith(prefix))
                    {
                        string strCreditCardInstitute = creditCardInfo.strCreditCardInstitute;
                        traceManager.TraceLine(strCreditCardInstitute, TraceManager.VerboseMode.VeryVerbose);
                        return strCreditCardInstitute;
                    }
                }
            }

            throw new CreditCardValidationException("argument:1301", String.Format("institute for credit card number '{0}' could not be found", creditCardNumber), creditCardNumber);
        }

        public void Validate(string creditCardNumber)
        {
            // validation
            if (String.IsNullOrEmpty(creditCardNumber)) throw new NullReferenceException("credit card number must not be empty");
            ValidateRegExCreditCardNumber(creditCardNumber);
            ValidateCreditCardNumberLength(creditCardNumber);

            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(String.Format("credit card number: {0}", creditCardNumber), TraceManager.VerboseMode.VeryVerbose);

            // collect info about credit card
            CreditCardInfo creditCardInfo = GetCreditCardInfo(creditCardNumber);

            traceManager.TraceLine(String.Format("credit card type:   {0}", creditCardInfo.strCreditCardInstitute), TraceManager.VerboseMode.VeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVerbose);

            // check out if prefix must be considered while computing the checksum
            string creditCardNumberToValidate = null;

            if (creditCardInfo.considerPrefixForValidation)
            {
                creditCardNumberToValidate = creditCardNumber;
            }
            else
            {
                foreach (string prefix in creditCardInfo.prefixes)
                {
                    if (creditCardNumber.StartsWith(prefix))
                    {
                        creditCardNumberToValidate = creditCardNumber.Substring(prefix.Length);
                        break;
                    }
                }
            }

            if (creditCardNumberToValidate == null) throw new CreditCardValidationException("argument:1302", String.Format("internal error -> credit card number to validate failed for '{0}'", creditCardNumber), creditCardNumber);

            traceManager.TraceLine(String.Format("relevant digits:    {0}", creditCardNumberToValidate), TraceManager.VerboseMode.VeryVeryVerbose);
            traceManager.TraceLine(TraceManager.VerboseMode.VeryVeryVerbose);

            // weighting
            byte[] weighting = { 1, 2 };

            // algorithm      
            byte[] creditCardNumberRelevantDigits = validationUtilities.GetByteArrayOfString(creditCardNumberToValidate);
            validationUtilities.MultiplyCyclicFromRightToLeftDigitByDigit(creditCardNumberRelevantDigits, weighting);
            validationUtilities.ComputeCrossSumForEachDigit(creditCardNumberRelevantDigits);
            int sum = validationUtilities.AddAllValues(creditCardNumberRelevantDigits);

            if (sum % 10 == 0)
            {
                traceManager.TraceLine("checksum:           --> OK", TraceManager.VerboseMode.VeryVerbose);
            }
            else
            {
                throw new CreditCardValidationException("validation:3302", String.Format("parity failure -> computed checksum = '{0}' <> '0'", (sum % 10).ToString()), creditCardNumber);
            }
        }

        // validates credit card number against regular expression. 
        // throws ArgumentException if match fails.
        private void ValidateRegExCreditCardNumber(string creditCardNumber)
        {
            RegexChecker.ValidateCreditCard(creditCardNumber);

            // special business rule for JCB
            if (creditCardNumber.StartsWith("2131") || creditCardNumber.StartsWith("1800"))
            {
                if (creditCardNumber.Length != 15) throw new ChecksumException("argument:1306", String.Format("invalid credit card number '{0}' -> type is 'JCB' but credit card number has only got {1} digits", creditCardNumber, creditCardNumber.Length.ToString()));
            }
            else if (creditCardNumber.StartsWith("3088"))
            {
                if (creditCardNumber.Length != 16) throw new ChecksumException("argument:1307", String.Format("invalid credit card number '{0}' -> type is 'JCB' but credit card number has only got {1} digits", creditCardNumber, creditCardNumber.Length.ToString()));
            }
        }

        // validates length of credit card number
        private void ValidateCreditCardNumberLength(string creditCardNumber)
        {
            CreditCardInfo info = GetCreditCardInfo(creditCardNumber);

            if (creditCardNumber.Length != info.length)
            {
                // exception to the rule
                if ((info.creditCardInstitute == CreditCardInstitute.Visa) && (creditCardNumber.Length == 13))
                {
                    // length 13 is also allowed for VISA
                }
                else
                {
                    throw new ChecksumException("argument:1308", String.Format("invalid credit card number '{0}' -> type is '{1}' but credit card number doesn't consist of exacly {2} digits", creditCardNumber, info.strCreditCardInstitute, info.length.ToString()));
                }
            }
        }

        // retrieves info object for given credit card number
        private CreditCardInfo GetCreditCardInfo(string creditCardNumber)
        {
            foreach (Object key in creditCards.Keys)
            {
                CreditCardInstitute creditCardInstitute = (CreditCardInstitute)key;
                CreditCardInfo info = (CreditCardInfo)(creditCards[creditCardInstitute]);

                string[] prefixes = info.prefixes;
                foreach (string strPrefix in prefixes)
                {
                    if (creditCardNumber.StartsWith(strPrefix)) return info;
                }
            }

            throw new CreditCardValidationException("argument:1303", String.Format("institute for credit card number '{0}' could not be found", creditCardNumber), creditCardNumber);
        }


    }
}
