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
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using ChecksumValidation.Security;

namespace ChecksumValidation.ChecksumClient
{
    public partial class MainForm : Form
    {
        // commands
        private const string cCmdLoadBankDirectory = "Load Bank Directory";
        private const string cCmdValidateAccount = "Validate Account";
        private const string cCmdFormatBlz = "Format BLZ";
        private const string cCmdValidateIban = "Validate IBAN";
        private const string cCmdToIban = "To IBAN";
        private const string cCmdFormatIban = "Format IBAN";
        private const string cCmdValidateGermanIdentityCard = "Validate German Identity Card";
        private const string cCmdValidateGermanPassport = "Validate German Passport";
        private const string cCmdValidateCreditCard = "Validate Credit Card";
        private const string cCmdGetCreditCardType = "Get Credit Card Type";
        private const string cCmdStop = "stop";

        private Hashtable commandMappings;

        // communication modes
        private const string cComInproc = "In-Proc";
        private const string cComTcp = "TCP";
        private const string cComSoap = "SOAP";
        private const string cComCom = "COM";

        private Hashtable communicationMappings;

        // private members
        private SecurityController securityController;
        private ParameterSet parameterSet;
        private TraceManager traceManager;
        private IProxy proxy;

        // ctor
        internal MainForm(SecurityController securityController, ParameterSet parameterSet, TraceManager traceManager)
        {
            if (securityController == null) throw new NullReferenceException("security controller not set!");
            if (parameterSet == null) throw new NullReferenceException("parameters not set!");
            if (traceManager == null) throw new NullReferenceException("trace manager not set!");
            
            this.securityController = securityController;
            this.parameterSet = parameterSet;
            this.traceManager = traceManager;
            this.proxy = null;

            // command mappings
            this.commandMappings = new Hashtable();

            this.commandMappings.Add(cCmdLoadBankDirectory, ChecksumValidation.CommandHandler.cCmdCache);
            this.commandMappings.Add(cCmdValidateAccount, ChecksumValidation.CommandHandler.cCmdAccount);
            this.commandMappings.Add(cCmdFormatBlz, ChecksumValidation.CommandHandler.cCmdFormatBlz);
            this.commandMappings.Add(cCmdValidateIban, ChecksumValidation.CommandHandler.cCmdIban);
            this.commandMappings.Add(cCmdToIban, ChecksumValidation.CommandHandler.cCmdToIban);
            this.commandMappings.Add(cCmdFormatIban, ChecksumValidation.CommandHandler.cCmdFormatIban);
            this.commandMappings.Add(cCmdValidateGermanIdentityCard, ChecksumValidation.CommandHandler.cCmdIdentity);
            this.commandMappings.Add(cCmdValidateGermanPassport, ChecksumValidation.CommandHandler.cCmdPassport);
            this.commandMappings.Add(cCmdValidateCreditCard, ChecksumValidation.CommandHandler.cCmdCreditCard);
            this.commandMappings.Add(cCmdGetCreditCardType, ChecksumValidation.CommandHandler.cCmdGetCreditCardType);

            this.communicationMappings = new Hashtable();

            this.communicationMappings.Add(cComInproc, ParameterSet.CommunicationMode.InProc);
            this.communicationMappings.Add(cComTcp, ParameterSet.CommunicationMode.Tcp);
            this.communicationMappings.Add(cComSoap, ParameterSet.CommunicationMode.Soap);
            this.communicationMappings.Add(cComCom, ParameterSet.CommunicationMode.Com);

            // initialize
            InitializeComponent();
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            // populate commands
            cboCommand.Items.Clear();
            foreach (string command in commandMappings.Keys) { cboCommand.Items.Add(command); }
            cboCommand.SelectedItem = cCmdValidateIban;

            // populate communication modes
            cboCommunication.Items.Clear();
            foreach (string communication in communicationMappings.Keys) { cboCommunication.Items.Add(communication); }
            cboCommunication.SelectedItem = cComInproc;

            // pre-set server communication 
            rdoInsecureConnection.Checked = true;
            txtBankDirectory.Text = parameterSet.BankDirectory;
            txtTcpServer.Text = parameterSet.TcpServer;
            txtTcpPort.Text = parameterSet.TcpPort.ToString();
            txtSoapEndpoint.Text = parameterSet.SoapEndpoint;
        }

        private void btnCommand_Click(object sender, EventArgs e)
        {
            txtResult.Clear();

            // validation
            string warning;
            string command;
            bool validUserInput = IsUserInputValid(out warning, out command);
            if (!validUserInput)
            {
                MessageBox.Show(warning, "Validation", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                // set encryption
                securityController.IsSecureConnection = (rdoSecureConnection.Checked);

                // set passphrase for TCP server
                if (cboCommunication.SelectedItem != null)
                {
                    string selectedCommunication = (string)cboCommunication.SelectedItem;
                    if (selectedCommunication.Equals(cComTcp) || selectedCommunication.Equals(cComSoap))
                    {
                        if (rdoInsecureConnection.Checked)
                        {
                            string password = txtSecurityPassword.Text;
                            string verifyPassword = (string)password.Clone();
                            securityController.SetCipherKey(ref password, ref verifyPassword);

                            // validate passphrase
                            securityController.Validate();
                        }
                    }
                }

                // command
                string userCommand = (string)cboCommand.SelectedItem;
                string internalCommand = command;

                // communication
                string userCommunication = (string)cboCommunication.SelectedItem;
                ParameterSet.CommunicationMode internalCommunication = (ParameterSet.CommunicationMode)communicationMappings[userCommunication];

                // soap
                parameterSet.SoapEndpoint = txtSoapEndpoint.Text;

                // bank directory
                parameterSet.BankDirectory = txtBankDirectory.Text;

                // proxy
                if (proxy == null) proxy = CommandHandler.CreateProxy(securityController, internalCommunication, parameterSet, traceManager);

                Application.UseWaitCursor = true;
                string result = CommandHandler.HandleCommandThroughCommunicationChannel(proxy, internalCommand);
                
                txtResult.Text = result;

                if (!parameterSet.Silent)
                {
                    traceManager.TraceLine(txtResult.Text, TraceManager.VerboseMode.Verbose);
                    traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.Verbose);
                }
            }
            catch (Exception ex)
            {
                txtResult.Text = "error: " + ex.Message;

                if (ex.InnerException != null)
                {
                    txtResult.Text += Environment.NewLine;
                    txtResult.Text += ex.InnerException.Message;
                }

                traceManager.TraceLine(txtResult.Text, TraceManager.VerboseMode.None);
                traceManager.TraceLine("-".PadRight(80, '-'), TraceManager.VerboseMode.None);
            }
            finally
            {
                Application.UseWaitCursor = false;
            }

        }

        private bool IsUserInputValid(out string warning, out string command)
        {
            warning = String.Empty;
            command = String.Empty;

            // communication parameters
            if (cboCommunication.SelectedIndex < 0)
            {
                warning = "Please select a communication channel!";
                return false;
            }

            string userCommunication = (string)cboCommunication.SelectedItem;
            ParameterSet.CommunicationMode internalCommunication = (ParameterSet.CommunicationMode)communicationMappings[userCommunication];

            if (internalCommunication == ParameterSet.CommunicationMode.Tcp)
            {
                if (String.IsNullOrEmpty(txtTcpServer.Text))
                {
                    warning = "Please specify the TCP server (ip address or host name)!";
                    return false;
                }

                if (String.IsNullOrEmpty(txtTcpPort.Text))
                {
                    warning = "Please specify the TCP port number!";
                    return false;
                }
            }

            if (internalCommunication == ParameterSet.CommunicationMode.Soap)
            {
                if (String.IsNullOrEmpty(txtSoapEndpoint.Text))
                {
                    warning = "Please specify the SOAP endpoint (full URL)!";
                    return false;
                }
            }

            // command
            if (cboCommand.SelectedIndex < 0)
            {
                warning = "Please select a command!";
                return false;
            }

            string userCommand = (string)cboCommand.SelectedItem;
            string internalCommand = (string)commandMappings[userCommand];

            if (userCommand.Equals(cCmdLoadBankDirectory)) 
            {
                command = internalCommand;
            }
            else if (userCommand.Equals(cCmdValidateAccount)) 
            {
                if (String.IsNullOrEmpty(txtAccount.Text))
                {
                    warning = "Please enter an account number!";
                    return false;
                }

                if (String.IsNullOrEmpty(txtBlz.Text))
                {
                    warning = "Please enter a blz!";
                    return false;
                }

                command = internalCommand + txtAccount.Text + "/" + txtBlz.Text;
            }
            else if (userCommand.Equals(cCmdFormatBlz)) 
            {
                if (String.IsNullOrEmpty(txtBlz.Text))
                {
                    warning = "Please enter a blz!";
                    return false;
                }

                command = internalCommand + txtBlz.Text;
            }
            else if (userCommand.Equals(cCmdValidateIban))
            {
                if (String.IsNullOrEmpty(txtIban.Text))
                {
                    warning = "Please enter an iban!";
                    return false;
                }

                command = internalCommand + txtIban.Text;
            }
            else if (userCommand.Equals(cCmdToIban)) 
            {
                if (String.IsNullOrEmpty(txtAccount.Text))
                {
                    warning = "Please enter an account number!";
                    return false;
                }

                if (String.IsNullOrEmpty(txtBlz.Text))
                {
                    warning = "Please enter a blz!";
                    return false;
                }

                command = internalCommand + txtAccount.Text + "/" + txtBlz.Text;
            }
            else if (userCommand.Equals(cCmdFormatIban)) 
            {
                if (String.IsNullOrEmpty(txtIban.Text))
                {
                    warning = "Please enter an iban!";
                    return false;
                }

                command = internalCommand + txtIban.Text;
            }
            else if (userCommand.Equals(cCmdValidateGermanIdentityCard)) 
            {
                if (String.IsNullOrEmpty(txtIdentity.Text))
                {
                    warning = "Please enter an id for a german identity card!";
                    return false;
                }

                command = internalCommand + txtIdentity.Text;
            }
            else if (userCommand.Equals(cCmdValidateGermanPassport)) 
            {
                if (String.IsNullOrEmpty(txtPassport.Text))
                {
                    warning = "Please enter an id for a german passport!";
                    return false;
                }

                command = internalCommand + txtPassport.Text;
            }
            else if (userCommand.Equals(cCmdValidateCreditCard)) 
            {
                if (String.IsNullOrEmpty(txtCreditCard.Text))
                {
                    warning = "Please enter an id for a german passport!";
                    return false;
                }

                command = internalCommand + txtCreditCard.Text;
            }
            else if (userCommand.Equals(cCmdGetCreditCardType)) 
            {
                if (String.IsNullOrEmpty(txtCreditCard.Text))
                {
                    warning = "Please enter an id for a german passport!";
                    return false;
                }

                command = internalCommand + txtCreditCard.Text;
            }
            else if (userCommand.Equals(cCmdStop))
            {
                command = internalCommand;
            }
            else
            {
                throw new Exception("invalid command!");
            }

            return true;
        }

        private void cboCommunication_SelectedIndexChanged(object sender, EventArgs e)
        {
            this.proxy = null;
        }

        private void txtSoapEndpoint_TextChanged(object sender, EventArgs e)
        {
            this.proxy = null;
        }

        private void txtSecurityPassword_TextChanged(object sender, EventArgs e)
        {
            this.proxy = null;
        }

        private void rdoSecureConnection_CheckedChanged(object sender, EventArgs e)
        {
            this.proxy = null;
        }

        private void rdoInsecureConnection_CheckedChanged(object sender, EventArgs e)
        {
            this.proxy = null;
        }

    }
}