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
using System.EnterpriseServices;
using System.IO;
using System.Security;
using System.Web.Services;
using System.Web.Services.Protocols;

using ChecksumValidation;
using ChecksumValidation.BankAccountValidation;
using ChecksumValidation.CreditCardValidation;
using ChecksumValidation.IbanValidation;
using ChecksumValidation.IdentityValidation;

public class SecuritySettings : SoapHeader
{
    public string secureConnection;
}

[WebService(Namespace = "http://www.ethical-hacking.de/ChecksumValidation/",
            Description="This web service validates german bank accounts by computing a checksum according to the algorithms maintained and documented by www.bundesbank.de. Also validates german identity cards, german passports, international bank accounts (IBAN) and credit cards.",
            Name="ChecksumValidation")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
public class Service : WebService
{
    // soap header
    public SecuritySettings securitySettings;

    // private constants
    private const string cDefaultBankDirectory = ".";
    private const string cResponseOk = "ok";

    // private members
    TraceManager traceManager = null;
    BankAccountValidator bankAccountValidator = null;
    IbanValidator ibanValidator = null;
    CreditCardValidator creditCardValidator = null;
    IdentityValidator identityValidator = null;

    // ctor
    public Service()
    {
        // tracing
        traceManager = new TraceManager(TraceManager.VerboseMode.None, Console.Out);

        // bank directory
        string bankDirectory = ConfigurationManager.AppSettings["bank-directory"];
        if (String.IsNullOrEmpty(bankDirectory)) bankDirectory = cDefaultBankDirectory;

        // validators
        bankAccountValidator = new BankAccountValidator(traceManager, bankDirectory);
        ibanValidator = new IbanValidator(traceManager);
        creditCardValidator = new CreditCardValidator(traceManager);
        identityValidator = new IdentityValidator(traceManager);
    }

    // soap interface
    [WebMethod(Description = "This web service loads the bank directory (for testing purposes only, no caching for stateless web service possible).",
               MessageName = "LoadBankDirectory",
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
               CacheDuration = 0,
               BufferResponse = true)]
    [SoapHeader("securitySettings", Direction=SoapHeaderDirection.In)]
    public string LoadBankDirectory()
    {
        try
        {
            VerifySecuritySettings();

            bankAccountValidator.Load();
            return cResponseOk;
        }
        catch (BankException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service validates a german bank code against an account number by computing a checksum and comparing it to the given checksum within the account number. The algorithms used to compute checksums are maintained by www.bundesbank.de. " +
                             "Sample: blz = 37050299/ account = 1234567897",
               MessageName="ValidateBankAccount",
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
               CacheDuration = 0,
               BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string ValidateBankAccount(string blz, string account)
    {
        try
        {
            VerifySecuritySettings();

            bankAccountValidator.Load();
            bankAccountValidator.Validate(blz, account);

            return cResponseOk;
        }
        catch (BankException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service formats a german bank code into its standard string representation. " +
                             "Sample: blz = 37050299",
               MessageName="FormatBlz",   
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
               CacheDuration = 0,
               BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string FormatBlz(string blz)
    {
        try
        {
            VerifySecuritySettings();

            return bankAccountValidator.FormatBlz(blz);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service computes an international bank account number (IBAN) from a german bank code and account number. " +
                            "Sample: blz = 37050299, account = 1234567890",
               MessageName="ToIban",
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
               CacheDuration = 0,
               BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string ToIban(string blz, string account)
    {
        try
        {
            VerifySecuritySettings();

            string iban = ibanValidator.ToIban(blz, account);
            return iban;
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service validates an international bank account number (IBAN). It computes a checksum for all " +
                             "characters of the (unformatted) IBAN, as described in ISO 13616 and EBS (European Banking Standard), " +
                             "and compares that checksum to the one provided within the IBAN. Algorithms are provided for the following " +
                             "countries: Belgium, Denmark, Germany, Finland, France, Great Britain, Ireland, Iceland, Italy, Luxembourg, " +
                             "Netherlands, Norway, Austria, Poland, Portugal, Sweden, Switzerland, Spain. " +
                             "Sample: iban = DE60700517550000007229",
               MessageName="ValidateIban",
               EnableSession = false,
              TransactionOption = TransactionOption.Disabled,
              CacheDuration = 0,
              BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string ValidateIban(string iban)
    {
        try
        {
            VerifySecuritySettings();

            ibanValidator.Validate(iban);
            return cResponseOk;
        }
        catch (IbanValidationException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service formats an international bank account number (IBAN) the way it's got to be printed on a document. " +
                             "Sample: iban = DE60700517550000007229",
               MessageName="FormatIban",
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
              CacheDuration = 0,
              BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string FormatIban(string iban)
    {
        try
        {
            VerifySecuritySettings();

            string formattedIban = ibanValidator.FormatIban(iban);
            return formattedIban;
        }
        catch (IbanValidationException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service validates a credit card number. It checks the type of the credit card (e.g. Visa) " +
                             "and computes its checksum. This checksum is then compared to the one provided within the credit card " +
                             "number. Currently, this web service supports American Express, Diner's Club, Discover, EnRoute, JCB, MasterCard, Visa, " +
                             "Bahncard and Miles & More. Please recognize that EuroCards and CrediCards are treated as MasterCards. " +
                             "Sample: creditCardNumber = 4509472140549006",
               MessageName="ValidateCreditCard",
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
               CacheDuration = 0,
               BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string ValidateCreditCard(string creditCardNumber)
    {
        try
        {
            VerifySecuritySettings();

            creditCardValidator.Validate(creditCardNumber);
            return cResponseOk;
        }
        catch (CreditCardValidationException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service retrieves the type of the credit card (e.g. Visa). " +
                             "Sample: creditCardNumber = 4509472140549006",
               MessageName="GetCreditCardType",
              EnableSession = false,
              TransactionOption = TransactionOption.Disabled,
              CacheDuration = 0,
              BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string GetCreditCardType(string creditCardNumber)
    {
        try
        {
            VerifySecuritySettings();

            string creditCardType = creditCardValidator.GetCreditCardType(creditCardNumber);
            return creditCardType;
        }
        catch (CreditCardValidationException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service validates a german identity card id. " +
                             "Sample: identityId = 2406055684D<<6810203<0705109<<<<<<6",
               MessageName="ValidateGermanIdentityCard",
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
               CacheDuration = 0,
               BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string ValidateGermanIdentityCard(string identityId)
    {
        try
        {
            VerifySecuritySettings();

            identityValidator.Validate(IdentityValidator.IdentityType.GermanIdentityCard, identityId);
            return cResponseOk;
        }
        catch (IdentityValidationException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    [WebMethod(Description = "This web service validates a german passport id. " +
                             "Sample: identityId = 2406055684D<<6810203M0705109<<<<<<<<<<<<<<<6",
               MessageName="ValidateGermanPassport",
               EnableSession = false,
               TransactionOption = TransactionOption.Disabled,
               CacheDuration = 0,
               BufferResponse = true)]
    [SoapHeader("securitySettings", Direction = SoapHeaderDirection.In)]
    public string ValidateGermanPassport(string identityId)
    {
        try
        {
            VerifySecuritySettings();

            identityValidator.Validate(IdentityValidator.IdentityType.GermanPassport, identityId);
            return cResponseOk;
        }
        catch (IdentityValidationException ex)
        {
            throw new SoapException("validation failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ChecksumException ex)
        {
            throw new SoapException("syntactical check failed!", SoapException.ClientFaultCode, ex);
        }
        catch (ArgumentException ex)
        {
            throw new SoapException("invalid argument!", SoapException.ClientFaultCode, ex);
        }
        catch (NullReferenceException ex)
        {
            throw new SoapException("invalid argument (must not be null)!", SoapException.ClientFaultCode, ex);
        }
        catch (SecurityException sex)
        {
            throw new SoapException("security error!", SoapException.ClientFaultCode, sex);
        }
        catch (Exception ex)
        {
            throw new SoapException("internal error!", SoapException.ClientFaultCode, ex);
        }
    }

    // helper: security settings
    private void VerifySecuritySettings()
    {
        string exceptionMessage = String.Empty;

        if (securitySettings == null)
        {
            if ((Context != null) && (Context.Request != null) && Context.Request.IsSecureConnection)
            {
                // ok, secure https connection
            }
            else
            {
                exceptionMessage = "missing soap header";
            }
        }
        else
        {
            if (String.IsNullOrEmpty(securitySettings.secureConnection)) exceptionMessage = "missing security setting in soap header";

            if (!securitySettings.secureConnection.Equals("true", StringComparison.CurrentCultureIgnoreCase) &&
                !securitySettings.secureConnection.Equals("yes", StringComparison.CurrentCultureIgnoreCase) &&
                !securitySettings.secureConnection.Equals("ok", StringComparison.CurrentCultureIgnoreCase) &&
                !securitySettings.secureConnection.Equals("1", StringComparison.CurrentCultureIgnoreCase))
            {
                exceptionMessage = String.Format("invalid soap header '{0}'", securitySettings.secureConnection);
            }
        }

        if (!String.IsNullOrEmpty(exceptionMessage)) throw new SecurityException(exceptionMessage);
    }

}
