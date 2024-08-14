using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Utils.Models
{
    public class Slip21Schema(string firstLevelLabel)
	{
		public string FirstLevelLabel { get; private set; } = firstLevelLabel;
	}
}
