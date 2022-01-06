using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Models
{
    public class Slip21Schema
    {
        public string FirstLevelLabel { get; private set; }

        public Slip21Schema(string firstLevelLabel)
        {
            FirstLevelLabel = firstLevelLabel;
        }
    }
}
