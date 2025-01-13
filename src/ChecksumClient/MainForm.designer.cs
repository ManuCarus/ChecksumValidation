namespace ChecksumValidation.ChecksumClient
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.grpChecksumValidation = new System.Windows.Forms.GroupBox();
            this.txtResult = new System.Windows.Forms.TextBox();
            this.lblResult = new System.Windows.Forms.Label();
            this.btnCommand = new System.Windows.Forms.Button();
            this.cboCommand = new System.Windows.Forms.ComboBox();
            this.lblCommand = new System.Windows.Forms.Label();
            this.cboCommunication = new System.Windows.Forms.ComboBox();
            this.lblCommunication = new System.Windows.Forms.Label();
            this.txtPassport = new System.Windows.Forms.TextBox();
            this.lblPassport = new System.Windows.Forms.Label();
            this.txtIdentity = new System.Windows.Forms.TextBox();
            this.lblIdentity = new System.Windows.Forms.Label();
            this.txtCreditCard = new System.Windows.Forms.TextBox();
            this.lblCreditCard = new System.Windows.Forms.Label();
            this.txtIban = new System.Windows.Forms.TextBox();
            this.lblIban = new System.Windows.Forms.Label();
            this.txtAccount = new System.Windows.Forms.TextBox();
            this.txtBlz = new System.Windows.Forms.TextBox();
            this.lblBlz = new System.Windows.Forms.Label();
            this.lblAccount = new System.Windows.Forms.Label();
            this.grpTcpServerCommunication = new System.Windows.Forms.GroupBox();
            this.txtSecurityPassword = new System.Windows.Forms.TextBox();
            this.rdoInsecureConnection = new System.Windows.Forms.RadioButton();
            this.rdoSecureConnection = new System.Windows.Forms.RadioButton();
            this.txtTcpPort = new System.Windows.Forms.TextBox();
            this.txtTcpServer = new System.Windows.Forms.TextBox();
            this.lblTcpPort = new System.Windows.Forms.Label();
            this.lblTcpServer = new System.Windows.Forms.Label();
            this.txtBankDirectory = new System.Windows.Forms.TextBox();
            this.lblBankDirectory = new System.Windows.Forms.Label();
            this.txtSoapEndpoint = new System.Windows.Forms.TextBox();
            this.lblSoapEndpoint = new System.Windows.Forms.Label();
            this.grpSoapServerCommunication = new System.Windows.Forms.GroupBox();
            this.grpInProcCommunication = new System.Windows.Forms.GroupBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.grpChecksumValidation.SuspendLayout();
            this.grpTcpServerCommunication.SuspendLayout();
            this.grpSoapServerCommunication.SuspendLayout();
            this.grpInProcCommunication.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // grpChecksumValidation
            // 
            this.grpChecksumValidation.Controls.Add(this.txtResult);
            this.grpChecksumValidation.Controls.Add(this.lblResult);
            this.grpChecksumValidation.Controls.Add(this.btnCommand);
            this.grpChecksumValidation.Controls.Add(this.cboCommand);
            this.grpChecksumValidation.Controls.Add(this.lblCommand);
            this.grpChecksumValidation.Controls.Add(this.cboCommunication);
            this.grpChecksumValidation.Controls.Add(this.lblCommunication);
            this.grpChecksumValidation.Controls.Add(this.txtPassport);
            this.grpChecksumValidation.Controls.Add(this.lblPassport);
            this.grpChecksumValidation.Controls.Add(this.txtIdentity);
            this.grpChecksumValidation.Controls.Add(this.lblIdentity);
            this.grpChecksumValidation.Controls.Add(this.txtCreditCard);
            this.grpChecksumValidation.Controls.Add(this.lblCreditCard);
            this.grpChecksumValidation.Controls.Add(this.txtIban);
            this.grpChecksumValidation.Controls.Add(this.lblIban);
            this.grpChecksumValidation.Controls.Add(this.txtAccount);
            this.grpChecksumValidation.Controls.Add(this.txtBlz);
            this.grpChecksumValidation.Controls.Add(this.lblBlz);
            this.grpChecksumValidation.Controls.Add(this.lblAccount);
            this.grpChecksumValidation.Location = new System.Drawing.Point(12, 12);
            this.grpChecksumValidation.Name = "grpChecksumValidation";
            this.grpChecksumValidation.Size = new System.Drawing.Size(439, 408);
            this.grpChecksumValidation.TabIndex = 0;
            this.grpChecksumValidation.TabStop = false;
            this.grpChecksumValidation.Text = "Checksum Validation";
            // 
            // txtResult
            // 
            this.txtResult.Location = new System.Drawing.Point(128, 298);
            this.txtResult.Multiline = true;
            this.txtResult.Name = "txtResult";
            this.txtResult.ReadOnly = true;
            this.txtResult.Size = new System.Drawing.Size(295, 91);
            this.txtResult.TabIndex = 21;
            // 
            // lblResult
            // 
            this.lblResult.AutoSize = true;
            this.lblResult.Location = new System.Drawing.Point(7, 298);
            this.lblResult.Name = "lblResult";
            this.lblResult.Size = new System.Drawing.Size(40, 13);
            this.lblResult.TabIndex = 0;
            this.lblResult.Text = "Result:";
            // 
            // btnCommand
            // 
            this.btnCommand.Location = new System.Drawing.Point(128, 259);
            this.btnCommand.Name = "btnCommand";
            this.btnCommand.Size = new System.Drawing.Size(295, 23);
            this.btnCommand.TabIndex = 20;
            this.btnCommand.Text = "Execute Command!";
            this.btnCommand.UseVisualStyleBackColor = true;
            this.btnCommand.Click += new System.EventHandler(this.btnCommand_Click);
            // 
            // cboCommand
            // 
            this.cboCommand.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cboCommand.FormattingEnabled = true;
            this.cboCommand.Location = new System.Drawing.Point(128, 205);
            this.cboCommand.Name = "cboCommand";
            this.cboCommand.Size = new System.Drawing.Size(295, 21);
            this.cboCommand.Sorted = true;
            this.cboCommand.TabIndex = 19;
            // 
            // lblCommand
            // 
            this.lblCommand.AutoSize = true;
            this.lblCommand.Location = new System.Drawing.Point(7, 205);
            this.lblCommand.Name = "lblCommand";
            this.lblCommand.Size = new System.Drawing.Size(57, 13);
            this.lblCommand.TabIndex = 18;
            this.lblCommand.Text = "Command:";
            // 
            // cboCommunication
            // 
            this.cboCommunication.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cboCommunication.FormattingEnabled = true;
            this.cboCommunication.Location = new System.Drawing.Point(128, 232);
            this.cboCommunication.Name = "cboCommunication";
            this.cboCommunication.Size = new System.Drawing.Size(295, 21);
            this.cboCommunication.Sorted = true;
            this.cboCommunication.TabIndex = 2;
            this.cboCommunication.SelectedIndexChanged += new System.EventHandler(this.cboCommunication_SelectedIndexChanged);
            // 
            // lblCommunication
            // 
            this.lblCommunication.AutoSize = true;
            this.lblCommunication.Location = new System.Drawing.Point(7, 235);
            this.lblCommunication.Name = "lblCommunication";
            this.lblCommunication.Size = new System.Drawing.Size(82, 13);
            this.lblCommunication.TabIndex = 8;
            this.lblCommunication.Text = "Communication:";
            // 
            // txtPassport
            // 
            this.txtPassport.Location = new System.Drawing.Point(128, 173);
            this.txtPassport.Name = "txtPassport";
            this.txtPassport.Size = new System.Drawing.Size(295, 20);
            this.txtPassport.TabIndex = 11;
            this.txtPassport.Text = "2406055684D<<6810203M0705109<<<<<<<<<<<<<<<6";
            // 
            // lblPassport
            // 
            this.lblPassport.AutoSize = true;
            this.lblPassport.Location = new System.Drawing.Point(7, 176);
            this.lblPassport.Name = "lblPassport";
            this.lblPassport.Size = new System.Drawing.Size(51, 13);
            this.lblPassport.TabIndex = 10;
            this.lblPassport.Text = "Passport:";
            // 
            // txtIdentity
            // 
            this.txtIdentity.Location = new System.Drawing.Point(128, 142);
            this.txtIdentity.Name = "txtIdentity";
            this.txtIdentity.Size = new System.Drawing.Size(295, 20);
            this.txtIdentity.TabIndex = 9;
            this.txtIdentity.Text = "2406055684D<<6810203<0705109<<<<<<6";
            // 
            // lblIdentity
            // 
            this.lblIdentity.AutoSize = true;
            this.lblIdentity.Location = new System.Drawing.Point(7, 145);
            this.lblIdentity.Name = "lblIdentity";
            this.lblIdentity.Size = new System.Drawing.Size(44, 13);
            this.lblIdentity.TabIndex = 8;
            this.lblIdentity.Text = "Identity:";
            // 
            // txtCreditCard
            // 
            this.txtCreditCard.Location = new System.Drawing.Point(128, 111);
            this.txtCreditCard.Name = "txtCreditCard";
            this.txtCreditCard.Size = new System.Drawing.Size(295, 20);
            this.txtCreditCard.TabIndex = 7;
            this.txtCreditCard.Text = "4509472140549006";
            // 
            // lblCreditCard
            // 
            this.lblCreditCard.AutoSize = true;
            this.lblCreditCard.Location = new System.Drawing.Point(7, 114);
            this.lblCreditCard.Name = "lblCreditCard";
            this.lblCreditCard.Size = new System.Drawing.Size(62, 13);
            this.lblCreditCard.TabIndex = 6;
            this.lblCreditCard.Text = "Credit Card:";
            // 
            // txtIban
            // 
            this.txtIban.Location = new System.Drawing.Point(128, 80);
            this.txtIban.Name = "txtIban";
            this.txtIban.Size = new System.Drawing.Size(295, 20);
            this.txtIban.TabIndex = 5;
            this.txtIban.Text = "DE60700517550000007229";
            // 
            // lblIban
            // 
            this.lblIban.AutoSize = true;
            this.lblIban.Location = new System.Drawing.Point(7, 83);
            this.lblIban.Name = "lblIban";
            this.lblIban.Size = new System.Drawing.Size(35, 13);
            this.lblIban.TabIndex = 4;
            this.lblIban.Text = "IBAN:";
            // 
            // txtAccount
            // 
            this.txtAccount.Location = new System.Drawing.Point(128, 49);
            this.txtAccount.Name = "txtAccount";
            this.txtAccount.Size = new System.Drawing.Size(295, 20);
            this.txtAccount.TabIndex = 3;
            this.txtAccount.Text = "1234567897";
            // 
            // txtBlz
            // 
            this.txtBlz.Location = new System.Drawing.Point(128, 19);
            this.txtBlz.Name = "txtBlz";
            this.txtBlz.Size = new System.Drawing.Size(295, 20);
            this.txtBlz.TabIndex = 1;
            this.txtBlz.Text = "37050299";
            // 
            // lblBlz
            // 
            this.lblBlz.AutoSize = true;
            this.lblBlz.Location = new System.Drawing.Point(7, 22);
            this.lblBlz.Name = "lblBlz";
            this.lblBlz.Size = new System.Drawing.Size(30, 13);
            this.lblBlz.TabIndex = 0;
            this.lblBlz.Text = "BLZ:";
            // 
            // lblAccount
            // 
            this.lblAccount.AutoSize = true;
            this.lblAccount.Location = new System.Drawing.Point(7, 52);
            this.lblAccount.Name = "lblAccount";
            this.lblAccount.Size = new System.Drawing.Size(50, 13);
            this.lblAccount.TabIndex = 2;
            this.lblAccount.Text = "Account:";
            // 
            // grpTcpServerCommunication
            // 
            this.grpTcpServerCommunication.Controls.Add(this.txtTcpPort);
            this.grpTcpServerCommunication.Controls.Add(this.txtTcpServer);
            this.grpTcpServerCommunication.Controls.Add(this.lblTcpPort);
            this.grpTcpServerCommunication.Controls.Add(this.lblTcpServer);
            this.grpTcpServerCommunication.Location = new System.Drawing.Point(12, 485);
            this.grpTcpServerCommunication.Name = "grpTcpServerCommunication";
            this.grpTcpServerCommunication.Size = new System.Drawing.Size(439, 76);
            this.grpTcpServerCommunication.TabIndex = 1;
            this.grpTcpServerCommunication.TabStop = false;
            this.grpTcpServerCommunication.Text = "TCP Server Communication";
            // 
            // txtSecurityPassword
            // 
            this.txtSecurityPassword.Location = new System.Drawing.Point(128, 46);
            this.txtSecurityPassword.Name = "txtSecurityPassword";
            this.txtSecurityPassword.PasswordChar = '*';
            this.txtSecurityPassword.Size = new System.Drawing.Size(295, 20);
            this.txtSecurityPassword.TabIndex = 23;
            this.txtSecurityPassword.TextChanged += new System.EventHandler(this.txtSecurityPassword_TextChanged);
            // 
            // rdoInsecureConnection
            // 
            this.rdoInsecureConnection.AutoSize = true;
            this.rdoInsecureConnection.Checked = true;
            this.rdoInsecureConnection.Location = new System.Drawing.Point(12, 47);
            this.rdoInsecureConnection.Name = "rdoInsecureConnection";
            this.rdoInsecureConnection.Size = new System.Drawing.Size(115, 17);
            this.rdoInsecureConnection.TabIndex = 22;
            this.rdoInsecureConnection.TabStop = true;
            this.rdoInsecureConnection.Text = "Security Password:";
            this.rdoInsecureConnection.UseVisualStyleBackColor = true;
            this.rdoInsecureConnection.CheckedChanged += new System.EventHandler(this.rdoInsecureConnection_CheckedChanged);
            // 
            // rdoSecureConnection
            // 
            this.rdoSecureConnection.AutoSize = true;
            this.rdoSecureConnection.Location = new System.Drawing.Point(12, 24);
            this.rdoSecureConnection.Name = "rdoSecureConnection";
            this.rdoSecureConnection.Size = new System.Drawing.Size(116, 17);
            this.rdoSecureConnection.TabIndex = 12;
            this.rdoSecureConnection.TabStop = true;
            this.rdoSecureConnection.Text = "Secure Connection";
            this.rdoSecureConnection.UseVisualStyleBackColor = true;
            this.rdoSecureConnection.CheckedChanged += new System.EventHandler(this.rdoSecureConnection_CheckedChanged);
            // 
            // txtTcpPort
            // 
            this.txtTcpPort.Location = new System.Drawing.Point(128, 43);
            this.txtTcpPort.Name = "txtTcpPort";
            this.txtTcpPort.Size = new System.Drawing.Size(295, 20);
            this.txtTcpPort.TabIndex = 6;
            this.txtTcpPort.Text = "65535";
            // 
            // txtTcpServer
            // 
            this.txtTcpServer.Location = new System.Drawing.Point(128, 19);
            this.txtTcpServer.Name = "txtTcpServer";
            this.txtTcpServer.Size = new System.Drawing.Size(295, 20);
            this.txtTcpServer.TabIndex = 5;
            this.txtTcpServer.Text = "localhost";
            // 
            // lblTcpPort
            // 
            this.lblTcpPort.AutoSize = true;
            this.lblTcpPort.Location = new System.Drawing.Point(7, 46);
            this.lblTcpPort.Name = "lblTcpPort";
            this.lblTcpPort.Size = new System.Drawing.Size(29, 13);
            this.lblTcpPort.TabIndex = 2;
            this.lblTcpPort.Text = "Port:";
            // 
            // lblTcpServer
            // 
            this.lblTcpServer.AutoSize = true;
            this.lblTcpServer.Location = new System.Drawing.Point(7, 22);
            this.lblTcpServer.Name = "lblTcpServer";
            this.lblTcpServer.Size = new System.Drawing.Size(41, 13);
            this.lblTcpServer.TabIndex = 1;
            this.lblTcpServer.Text = "Server:";
            // 
            // txtBankDirectory
            // 
            this.txtBankDirectory.Location = new System.Drawing.Point(128, 19);
            this.txtBankDirectory.Name = "txtBankDirectory";
            this.txtBankDirectory.Size = new System.Drawing.Size(295, 20);
            this.txtBankDirectory.TabIndex = 4;
            // 
            // lblBankDirectory
            // 
            this.lblBankDirectory.AutoSize = true;
            this.lblBankDirectory.Location = new System.Drawing.Point(7, 22);
            this.lblBankDirectory.Name = "lblBankDirectory";
            this.lblBankDirectory.Size = new System.Drawing.Size(80, 13);
            this.lblBankDirectory.TabIndex = 0;
            this.lblBankDirectory.Text = "Bank Directory:";
            // 
            // txtSoapEndpoint
            // 
            this.txtSoapEndpoint.Location = new System.Drawing.Point(126, 19);
            this.txtSoapEndpoint.Name = "txtSoapEndpoint";
            this.txtSoapEndpoint.Size = new System.Drawing.Size(295, 20);
            this.txtSoapEndpoint.TabIndex = 7;
            this.txtSoapEndpoint.Text = "http://localhost:49152/Service.asmx";
            this.txtSoapEndpoint.TextChanged += new System.EventHandler(this.txtSoapEndpoint_TextChanged);
            // 
            // lblSoapEndpoint
            // 
            this.lblSoapEndpoint.AutoSize = true;
            this.lblSoapEndpoint.Location = new System.Drawing.Point(5, 22);
            this.lblSoapEndpoint.Name = "lblSoapEndpoint";
            this.lblSoapEndpoint.Size = new System.Drawing.Size(84, 13);
            this.lblSoapEndpoint.TabIndex = 3;
            this.lblSoapEndpoint.Text = "SOAP Endpoint:";
            // 
            // grpSoapServerCommunication
            // 
            this.grpSoapServerCommunication.Controls.Add(this.txtSoapEndpoint);
            this.grpSoapServerCommunication.Controls.Add(this.lblSoapEndpoint);
            this.grpSoapServerCommunication.Location = new System.Drawing.Point(12, 567);
            this.grpSoapServerCommunication.Name = "grpSoapServerCommunication";
            this.grpSoapServerCommunication.Size = new System.Drawing.Size(439, 50);
            this.grpSoapServerCommunication.TabIndex = 8;
            this.grpSoapServerCommunication.TabStop = false;
            this.grpSoapServerCommunication.Text = "SOAP Server Communication";
            // 
            // grpInProcCommunication
            // 
            this.grpInProcCommunication.Controls.Add(this.txtBankDirectory);
            this.grpInProcCommunication.Controls.Add(this.lblBankDirectory);
            this.grpInProcCommunication.Location = new System.Drawing.Point(12, 432);
            this.grpInProcCommunication.Name = "grpInProcCommunication";
            this.grpInProcCommunication.Size = new System.Drawing.Size(439, 47);
            this.grpInProcCommunication.TabIndex = 9;
            this.grpInProcCommunication.TabStop = false;
            this.grpInProcCommunication.Text = "In-Process and COM Communication";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.txtSecurityPassword);
            this.groupBox1.Controls.Add(this.rdoInsecureConnection);
            this.groupBox1.Controls.Add(this.rdoSecureConnection);
            this.groupBox1.Location = new System.Drawing.Point(12, 623);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(439, 76);
            this.groupBox1.TabIndex = 10;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Security Settings for TCP and SOAP Server Communication";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(466, 713);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.grpInProcCommunication);
            this.Controls.Add(this.grpSoapServerCommunication);
            this.Controls.Add(this.grpTcpServerCommunication);
            this.Controls.Add(this.grpChecksumValidation);
            this.Name = "MainForm";
            this.Text = "Checksum Client";
            this.Load += new System.EventHandler(this.MainForm_Load);
            this.grpChecksumValidation.ResumeLayout(false);
            this.grpChecksumValidation.PerformLayout();
            this.grpTcpServerCommunication.ResumeLayout(false);
            this.grpTcpServerCommunication.PerformLayout();
            this.grpSoapServerCommunication.ResumeLayout(false);
            this.grpSoapServerCommunication.PerformLayout();
            this.grpInProcCommunication.ResumeLayout(false);
            this.grpInProcCommunication.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox grpChecksumValidation;
        private System.Windows.Forms.GroupBox grpTcpServerCommunication;
        private System.Windows.Forms.Label lblIdentity;
        private System.Windows.Forms.TextBox txtCreditCard;
        private System.Windows.Forms.Label lblCreditCard;
        private System.Windows.Forms.TextBox txtIban;
        private System.Windows.Forms.Label lblIban;
        private System.Windows.Forms.TextBox txtAccount;
        private System.Windows.Forms.TextBox txtBlz;
        private System.Windows.Forms.Label lblBlz;
        private System.Windows.Forms.Label lblAccount;
        private System.Windows.Forms.TextBox txtPassport;
        private System.Windows.Forms.Label lblPassport;
        private System.Windows.Forms.TextBox txtIdentity;
        private System.Windows.Forms.ComboBox cboCommand;
        private System.Windows.Forms.Label lblCommand;
        private System.Windows.Forms.Button btnCommand;
        private System.Windows.Forms.TextBox txtResult;
        private System.Windows.Forms.Label lblResult;
        private System.Windows.Forms.Label lblSoapEndpoint;
        private System.Windows.Forms.Label lblTcpPort;
        private System.Windows.Forms.Label lblTcpServer;
        private System.Windows.Forms.Label lblBankDirectory;
        private System.Windows.Forms.TextBox txtSoapEndpoint;
        private System.Windows.Forms.TextBox txtTcpPort;
        private System.Windows.Forms.TextBox txtTcpServer;
        private System.Windows.Forms.TextBox txtBankDirectory;
        private System.Windows.Forms.ComboBox cboCommunication;
        private System.Windows.Forms.Label lblCommunication;
        private System.Windows.Forms.RadioButton rdoInsecureConnection;
        private System.Windows.Forms.RadioButton rdoSecureConnection;
        private System.Windows.Forms.TextBox txtSecurityPassword;
        private System.Windows.Forms.GroupBox grpSoapServerCommunication;
        private System.Windows.Forms.GroupBox grpInProcCommunication;
        private System.Windows.Forms.GroupBox groupBox1;
    }
}