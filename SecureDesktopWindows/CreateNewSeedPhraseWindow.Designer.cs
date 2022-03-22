namespace uk.JohnCook.dotnet.LTOEncryptionManager.SecureDesktopWindows
{
    partial class CreateNewSeedPhraseWindow
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.lblSeedHex1 = new System.Windows.Forms.Label();
            this.btnGenerateSeed = new System.Windows.Forms.Button();
            this.lblSeedHex2 = new System.Windows.Forms.Label();
            this.lblSeedHex3 = new System.Windows.Forms.Label();
            this.lblSeedHex4 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.tbGlobalRollovers = new System.Windows.Forms.TextBox();
            this.tbAccount = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.tbAccountRollovers = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.btnDeriveAccountNode = new System.Windows.Forms.Button();
            this.tbSeedFingerprint = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.tbAccountFingerprint = new System.Windows.Forms.TextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.gbSeedPhrase = new System.Windows.Forms.GroupBox();
            this.lblProcessCount = new System.Windows.Forms.Label();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.statusLabel = new System.Windows.Forms.ToolStripStatusLabel();
            this.gbSeedPhrase.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // lblSeedHex1
            // 
            this.lblSeedHex1.AutoSize = true;
            this.lblSeedHex1.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point);
            this.lblSeedHex1.Location = new System.Drawing.Point(14, 27);
            this.lblSeedHex1.Name = "lblSeedHex1";
            this.lblSeedHex1.Size = new System.Drawing.Size(0, 19);
            this.lblSeedHex1.TabIndex = 0;
            // 
            // btnGenerateSeed
            // 
            this.btnGenerateSeed.AutoSize = true;
            this.btnGenerateSeed.Enabled = false;
            this.btnGenerateSeed.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.btnGenerateSeed.Location = new System.Drawing.Point(16, 16);
            this.btnGenerateSeed.Name = "btnGenerateSeed";
            this.btnGenerateSeed.Size = new System.Drawing.Size(188, 32);
            this.btnGenerateSeed.TabIndex = 1;
            this.btnGenerateSeed.Text = "Generate 256-bit Seed";
            this.btnGenerateSeed.UseVisualStyleBackColor = true;
            this.btnGenerateSeed.Click += new System.EventHandler(this.BtnGenerateSeed_Click);
            // 
            // lblSeedHex2
            // 
            this.lblSeedHex2.AutoSize = true;
            this.lblSeedHex2.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point);
            this.lblSeedHex2.Location = new System.Drawing.Point(14, 54);
            this.lblSeedHex2.Name = "lblSeedHex2";
            this.lblSeedHex2.Size = new System.Drawing.Size(0, 19);
            this.lblSeedHex2.TabIndex = 2;
            // 
            // lblSeedHex3
            // 
            this.lblSeedHex3.AutoSize = true;
            this.lblSeedHex3.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point);
            this.lblSeedHex3.Location = new System.Drawing.Point(14, 81);
            this.lblSeedHex3.Name = "lblSeedHex3";
            this.lblSeedHex3.Size = new System.Drawing.Size(0, 19);
            this.lblSeedHex3.TabIndex = 3;
            // 
            // lblSeedHex4
            // 
            this.lblSeedHex4.AutoSize = true;
            this.lblSeedHex4.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point);
            this.lblSeedHex4.Location = new System.Drawing.Point(14, 108);
            this.lblSeedHex4.Name = "lblSeedHex4";
            this.lblSeedHex4.Size = new System.Drawing.Size(0, 19);
            this.lblSeedHex4.TabIndex = 4;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label1.Location = new System.Drawing.Point(16, 213);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(210, 22);
            this.label1.TabIndex = 5;
            this.label1.Text = "Global Key Rollover Count:";
            // 
            // tbGlobalRollovers
            // 
            this.tbGlobalRollovers.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.tbGlobalRollovers.Location = new System.Drawing.Point(232, 210);
            this.tbGlobalRollovers.Name = "tbGlobalRollovers";
            this.tbGlobalRollovers.ReadOnly = true;
            this.tbGlobalRollovers.Size = new System.Drawing.Size(95, 29);
            this.tbGlobalRollovers.TabIndex = 6;
            this.tbGlobalRollovers.Text = "0";
            this.tbGlobalRollovers.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // tbAccount
            // 
            this.tbAccount.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.tbAccount.Location = new System.Drawing.Point(118, 253);
            this.tbAccount.Name = "tbAccount";
            this.tbAccount.ReadOnly = true;
            this.tbAccount.Size = new System.Drawing.Size(209, 29);
            this.tbAccount.TabIndex = 8;
            this.tbAccount.Text = "0";
            this.tbAccount.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label2.Location = new System.Drawing.Point(16, 256);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(96, 22);
            this.label2.TabIndex = 7;
            this.label2.Text = "Account ID:";
            // 
            // tbAccountRollovers
            // 
            this.tbAccountRollovers.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.tbAccountRollovers.Location = new System.Drawing.Point(214, 296);
            this.tbAccountRollovers.Name = "tbAccountRollovers";
            this.tbAccountRollovers.ReadOnly = true;
            this.tbAccountRollovers.Size = new System.Drawing.Size(113, 29);
            this.tbAccountRollovers.TabIndex = 10;
            this.tbAccountRollovers.Text = "0";
            this.tbAccountRollovers.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label3.Location = new System.Drawing.Point(16, 299);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(192, 22);
            this.label3.TabIndex = 9;
            this.label3.Text = "Account Rollover Count:";
            // 
            // btnDeriveAccountNode
            // 
            this.btnDeriveAccountNode.AutoSize = true;
            this.btnDeriveAccountNode.Enabled = false;
            this.btnDeriveAccountNode.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.btnDeriveAccountNode.Location = new System.Drawing.Point(16, 339);
            this.btnDeriveAccountNode.Name = "btnDeriveAccountNode";
            this.btnDeriveAccountNode.Size = new System.Drawing.Size(180, 32);
            this.btnDeriveAccountNode.TabIndex = 11;
            this.btnDeriveAccountNode.Text = "Derive Account Node";
            this.btnDeriveAccountNode.UseVisualStyleBackColor = true;
            this.btnDeriveAccountNode.Click += new System.EventHandler(this.BtnDeriveAccountNode_Click);
            // 
            // tbSeedFingerprint
            // 
            this.tbSeedFingerprint.Font = new System.Drawing.Font("Consolas", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.tbSeedFingerprint.Location = new System.Drawing.Point(511, 210);
            this.tbSeedFingerprint.Name = "tbSeedFingerprint";
            this.tbSeedFingerprint.ReadOnly = true;
            this.tbSeedFingerprint.Size = new System.Drawing.Size(458, 30);
            this.tbSeedFingerprint.TabIndex = 13;
            this.tbSeedFingerprint.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label4.Location = new System.Drawing.Point(341, 213);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(139, 22);
            this.label4.TabIndex = 12;
            this.label4.Text = "Seed Fingerprint:";
            // 
            // tbAccountFingerprint
            // 
            this.tbAccountFingerprint.Font = new System.Drawing.Font("Consolas", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.tbAccountFingerprint.Location = new System.Drawing.Point(511, 296);
            this.tbAccountFingerprint.Name = "tbAccountFingerprint";
            this.tbAccountFingerprint.ReadOnly = true;
            this.tbAccountFingerprint.Size = new System.Drawing.Size(458, 30);
            this.tbAccountFingerprint.TabIndex = 15;
            this.tbAccountFingerprint.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Open Sans", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.label5.Location = new System.Drawing.Point(341, 299);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(164, 22);
            this.label5.TabIndex = 14;
            this.label5.Text = "Account Fingerprint:";
            // 
            // gbSeedPhrase
            // 
            this.gbSeedPhrase.Controls.Add(this.lblSeedHex1);
            this.gbSeedPhrase.Controls.Add(this.lblSeedHex2);
            this.gbSeedPhrase.Controls.Add(this.lblSeedHex3);
            this.gbSeedPhrase.Controls.Add(this.lblSeedHex4);
            this.gbSeedPhrase.Location = new System.Drawing.Point(16, 54);
            this.gbSeedPhrase.Name = "gbSeedPhrase";
            this.gbSeedPhrase.Size = new System.Drawing.Size(498, 140);
            this.gbSeedPhrase.TabIndex = 16;
            this.gbSeedPhrase.TabStop = false;
            this.gbSeedPhrase.Text = "BIP39 Seed Phrase";
            // 
            // lblProcessCount
            // 
            this.lblProcessCount.AutoSize = true;
            this.lblProcessCount.Font = new System.Drawing.Font("Open Sans", 11F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.lblProcessCount.Location = new System.Drawing.Point(222, 22);
            this.lblProcessCount.Name = "lblProcessCount";
            this.lblProcessCount.Size = new System.Drawing.Size(0, 20);
            this.lblProcessCount.TabIndex = 17;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.statusLabel});
            this.statusStrip1.Location = new System.Drawing.Point(0, 387);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(981, 22);
            this.statusStrip1.TabIndex = 18;
            this.statusStrip1.Text = "statusStrip";
            // 
            // statusLabel
            // 
            this.statusLabel.Font = new System.Drawing.Font("Open Sans", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);
            this.statusLabel.Name = "statusLabel";
            this.statusLabel.Size = new System.Drawing.Size(0, 17);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.ClientSize = new System.Drawing.Size(981, 409);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.lblProcessCount);
            this.Controls.Add(this.gbSeedPhrase);
            this.Controls.Add(this.tbAccountFingerprint);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.tbSeedFingerprint);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.btnDeriveAccountNode);
            this.Controls.Add(this.tbAccountRollovers);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.tbAccount);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.tbGlobalRollovers);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.btnGenerateSeed);
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Create New BIP39 Seed - Secure Window";
            this.gbSeedPhrase.ResumeLayout(false);
            this.gbSeedPhrase.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label lblSeedHex1;
        private System.Windows.Forms.Button btnGenerateSeed;
        private System.Windows.Forms.Label lblSeedHex2;
        private System.Windows.Forms.Label lblSeedHex3;
        private System.Windows.Forms.Label lblSeedHex4;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox tbGlobalRollovers;
        private System.Windows.Forms.TextBox tbAccount;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox tbAccountRollovers;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Button btnDeriveAccountNode;
        private System.Windows.Forms.TextBox tbSeedFingerprint;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox tbAccountFingerprint;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.GroupBox gbSeedPhrase;
        private System.Windows.Forms.Label lblProcessCount;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel statusLabel;
    }
}
