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
			lblSeedHex1 = new System.Windows.Forms.Label();
			btnGenerateSeed = new System.Windows.Forms.Button();
			lblSeedHex2 = new System.Windows.Forms.Label();
			lblSeedHex3 = new System.Windows.Forms.Label();
			lblSeedHex4 = new System.Windows.Forms.Label();
			label1 = new System.Windows.Forms.Label();
			tbGlobalRollovers = new System.Windows.Forms.TextBox();
			tbAccount = new System.Windows.Forms.TextBox();
			label2 = new System.Windows.Forms.Label();
			tbAccountRollovers = new System.Windows.Forms.TextBox();
			label3 = new System.Windows.Forms.Label();
			btnDeriveAccountNode = new System.Windows.Forms.Button();
			tbSeedFingerprint = new System.Windows.Forms.TextBox();
			label4 = new System.Windows.Forms.Label();
			tbAccountFingerprint = new System.Windows.Forms.TextBox();
			label5 = new System.Windows.Forms.Label();
			gbSeedPhrase = new System.Windows.Forms.GroupBox();
			lblProcessCount = new System.Windows.Forms.Label();
			statusStrip1 = new System.Windows.Forms.StatusStrip();
			statusLabel = new System.Windows.Forms.ToolStripStatusLabel();
			progressBar = new System.Windows.Forms.ToolStripProgressBar();
			gbSeedPhrase.SuspendLayout();
			statusStrip1.SuspendLayout();
			SuspendLayout();
			// 
			// lblSeedHex1
			// 
			lblSeedHex1.AutoSize = true;
			lblSeedHex1.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold);
			lblSeedHex1.Location = new System.Drawing.Point(14, 27);
			lblSeedHex1.Name = "lblSeedHex1";
			lblSeedHex1.Size = new System.Drawing.Size(0, 19);
			lblSeedHex1.TabIndex = 0;
			// 
			// btnGenerateSeed
			// 
			btnGenerateSeed.AutoSize = true;
			btnGenerateSeed.Enabled = false;
			btnGenerateSeed.Font = new System.Drawing.Font("Open Sans", 12F);
			btnGenerateSeed.Location = new System.Drawing.Point(16, 16);
			btnGenerateSeed.Name = "btnGenerateSeed";
			btnGenerateSeed.Size = new System.Drawing.Size(188, 32);
			btnGenerateSeed.TabIndex = 1;
			btnGenerateSeed.Text = "Generate 256-bit Seed";
			btnGenerateSeed.UseVisualStyleBackColor = true;
			btnGenerateSeed.Click += BtnGenerateSeed_Click;
			// 
			// lblSeedHex2
			// 
			lblSeedHex2.AutoSize = true;
			lblSeedHex2.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold);
			lblSeedHex2.Location = new System.Drawing.Point(14, 54);
			lblSeedHex2.Name = "lblSeedHex2";
			lblSeedHex2.Size = new System.Drawing.Size(0, 19);
			lblSeedHex2.TabIndex = 2;
			// 
			// lblSeedHex3
			// 
			lblSeedHex3.AutoSize = true;
			lblSeedHex3.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold);
			lblSeedHex3.Location = new System.Drawing.Point(14, 81);
			lblSeedHex3.Name = "lblSeedHex3";
			lblSeedHex3.Size = new System.Drawing.Size(0, 19);
			lblSeedHex3.TabIndex = 3;
			// 
			// lblSeedHex4
			// 
			lblSeedHex4.AutoSize = true;
			lblSeedHex4.Font = new System.Drawing.Font("Consolas", 12F, System.Drawing.FontStyle.Bold);
			lblSeedHex4.Location = new System.Drawing.Point(14, 108);
			lblSeedHex4.Name = "lblSeedHex4";
			lblSeedHex4.Size = new System.Drawing.Size(0, 19);
			lblSeedHex4.TabIndex = 4;
			// 
			// label1
			// 
			label1.AutoSize = true;
			label1.Font = new System.Drawing.Font("Open Sans", 12F);
			label1.Location = new System.Drawing.Point(16, 213);
			label1.Name = "label1";
			label1.Size = new System.Drawing.Size(210, 22);
			label1.TabIndex = 5;
			label1.Text = "Global Key Rollover Count:";
			// 
			// tbGlobalRollovers
			// 
			tbGlobalRollovers.Font = new System.Drawing.Font("Open Sans", 12F);
			tbGlobalRollovers.Location = new System.Drawing.Point(232, 210);
			tbGlobalRollovers.Name = "tbGlobalRollovers";
			tbGlobalRollovers.ReadOnly = true;
			tbGlobalRollovers.Size = new System.Drawing.Size(95, 29);
			tbGlobalRollovers.TabIndex = 6;
			tbGlobalRollovers.Text = "0";
			tbGlobalRollovers.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
			// 
			// tbAccount
			// 
			tbAccount.Font = new System.Drawing.Font("Open Sans", 12F);
			tbAccount.Location = new System.Drawing.Point(118, 253);
			tbAccount.Name = "tbAccount";
			tbAccount.ReadOnly = true;
			tbAccount.Size = new System.Drawing.Size(209, 29);
			tbAccount.TabIndex = 8;
			tbAccount.Text = "0";
			tbAccount.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
			// 
			// label2
			// 
			label2.AutoSize = true;
			label2.Font = new System.Drawing.Font("Open Sans", 12F);
			label2.Location = new System.Drawing.Point(16, 256);
			label2.Name = "label2";
			label2.Size = new System.Drawing.Size(96, 22);
			label2.TabIndex = 7;
			label2.Text = "Account ID:";
			// 
			// tbAccountRollovers
			// 
			tbAccountRollovers.Font = new System.Drawing.Font("Open Sans", 12F);
			tbAccountRollovers.Location = new System.Drawing.Point(214, 296);
			tbAccountRollovers.Name = "tbAccountRollovers";
			tbAccountRollovers.ReadOnly = true;
			tbAccountRollovers.Size = new System.Drawing.Size(113, 29);
			tbAccountRollovers.TabIndex = 10;
			tbAccountRollovers.Text = "0";
			tbAccountRollovers.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
			// 
			// label3
			// 
			label3.AutoSize = true;
			label3.Font = new System.Drawing.Font("Open Sans", 12F);
			label3.Location = new System.Drawing.Point(16, 299);
			label3.Name = "label3";
			label3.Size = new System.Drawing.Size(192, 22);
			label3.TabIndex = 9;
			label3.Text = "Account Rollover Count:";
			// 
			// btnDeriveAccountNode
			// 
			btnDeriveAccountNode.AutoSize = true;
			btnDeriveAccountNode.Enabled = false;
			btnDeriveAccountNode.Font = new System.Drawing.Font("Open Sans", 12F);
			btnDeriveAccountNode.Location = new System.Drawing.Point(16, 339);
			btnDeriveAccountNode.Name = "btnDeriveAccountNode";
			btnDeriveAccountNode.Size = new System.Drawing.Size(180, 32);
			btnDeriveAccountNode.TabIndex = 11;
			btnDeriveAccountNode.Text = "Derive Account Node";
			btnDeriveAccountNode.UseVisualStyleBackColor = true;
			btnDeriveAccountNode.Click += BtnDeriveAccountNode_Click;
			// 
			// tbSeedFingerprint
			// 
			tbSeedFingerprint.Font = new System.Drawing.Font("Consolas", 14.25F);
			tbSeedFingerprint.Location = new System.Drawing.Point(511, 210);
			tbSeedFingerprint.Name = "tbSeedFingerprint";
			tbSeedFingerprint.ReadOnly = true;
			tbSeedFingerprint.Size = new System.Drawing.Size(458, 30);
			tbSeedFingerprint.TabIndex = 13;
			tbSeedFingerprint.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
			// 
			// label4
			// 
			label4.AutoSize = true;
			label4.Font = new System.Drawing.Font("Open Sans", 12F);
			label4.Location = new System.Drawing.Point(341, 213);
			label4.Name = "label4";
			label4.Size = new System.Drawing.Size(139, 22);
			label4.TabIndex = 12;
			label4.Text = "Seed Fingerprint:";
			// 
			// tbAccountFingerprint
			// 
			tbAccountFingerprint.Font = new System.Drawing.Font("Consolas", 14.25F);
			tbAccountFingerprint.Location = new System.Drawing.Point(511, 296);
			tbAccountFingerprint.Name = "tbAccountFingerprint";
			tbAccountFingerprint.ReadOnly = true;
			tbAccountFingerprint.Size = new System.Drawing.Size(458, 30);
			tbAccountFingerprint.TabIndex = 15;
			tbAccountFingerprint.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
			// 
			// label5
			// 
			label5.AutoSize = true;
			label5.Font = new System.Drawing.Font("Open Sans", 12F);
			label5.Location = new System.Drawing.Point(341, 299);
			label5.Name = "label5";
			label5.Size = new System.Drawing.Size(164, 22);
			label5.TabIndex = 14;
			label5.Text = "Account Fingerprint:";
			// 
			// gbSeedPhrase
			// 
			gbSeedPhrase.Controls.Add(lblSeedHex1);
			gbSeedPhrase.Controls.Add(lblSeedHex2);
			gbSeedPhrase.Controls.Add(lblSeedHex3);
			gbSeedPhrase.Controls.Add(lblSeedHex4);
			gbSeedPhrase.Location = new System.Drawing.Point(16, 54);
			gbSeedPhrase.Name = "gbSeedPhrase";
			gbSeedPhrase.Size = new System.Drawing.Size(498, 140);
			gbSeedPhrase.TabIndex = 16;
			gbSeedPhrase.TabStop = false;
			gbSeedPhrase.Text = "BIP39 Seed Phrase";
			// 
			// lblProcessCount
			// 
			lblProcessCount.AutoSize = true;
			lblProcessCount.Font = new System.Drawing.Font("Open Sans", 11F);
			lblProcessCount.Location = new System.Drawing.Point(222, 22);
			lblProcessCount.Name = "lblProcessCount";
			lblProcessCount.Size = new System.Drawing.Size(0, 20);
			lblProcessCount.TabIndex = 17;
			// 
			// statusStrip1
			// 
			statusStrip1.Font = new System.Drawing.Font("Segoe UI", 10F);
			statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] { statusLabel, progressBar });
			statusStrip1.Location = new System.Drawing.Point(0, 387);
			statusStrip1.Name = "statusStrip1";
			statusStrip1.Size = new System.Drawing.Size(981, 22);
			statusStrip1.TabIndex = 18;
			statusStrip1.Text = "statusStrip";
			// 
			// statusLabel
			// 
			statusLabel.Font = new System.Drawing.Font("Segoe UI", 10F);
			statusLabel.Name = "statusLabel";
			statusLabel.Size = new System.Drawing.Size(833, 17);
			statusLabel.Spring = true;
			statusLabel.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
			// 
			// progressBar
			// 
			progressBar.Alignment = System.Windows.Forms.ToolStripItemAlignment.Right;
			progressBar.Name = "progressBar";
			progressBar.Size = new System.Drawing.Size(100, 16);
			// 
			// CreateNewSeedPhraseWindow
			// 
			AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
			AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			AutoSize = true;
			ClientSize = new System.Drawing.Size(981, 409);
			Controls.Add(statusStrip1);
			Controls.Add(lblProcessCount);
			Controls.Add(gbSeedPhrase);
			Controls.Add(tbAccountFingerprint);
			Controls.Add(label5);
			Controls.Add(tbSeedFingerprint);
			Controls.Add(label4);
			Controls.Add(btnDeriveAccountNode);
			Controls.Add(tbAccountRollovers);
			Controls.Add(label3);
			Controls.Add(tbAccount);
			Controls.Add(label2);
			Controls.Add(tbGlobalRollovers);
			Controls.Add(label1);
			Controls.Add(btnGenerateSeed);
			Name = "CreateNewSeedPhraseWindow";
			StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
			Text = "Create Account From New BIP39 Seed - Secure Window";
			gbSeedPhrase.ResumeLayout(false);
			gbSeedPhrase.PerformLayout();
			statusStrip1.ResumeLayout(false);
			statusStrip1.PerformLayout();
			ResumeLayout(false);
			PerformLayout();
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
		private System.Windows.Forms.ToolStripProgressBar progressBar;
	}
}
