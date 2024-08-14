﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Models
{
	public class TapeDriveErrorEventArgs(string errorString) : EventArgs
	{
		public string ErrorString { get; set; } = errorString;
	}
}
