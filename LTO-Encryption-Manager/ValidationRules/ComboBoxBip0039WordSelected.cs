using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.ValidationRules
{
    public class ComboBoxBip0039WordSelected : ValidationRule
    {
        public override ValidationResult Validate(object value, CultureInfo cultureInfo)
        {
            if (value is null)
            {
                return new ValidationResult(false, Properties.Resources.validation_error_ComboBoxNotBip0039Word);
            }
            else if (value is string @string)
            {
                return Wallet.Bip0039Dictionaries.AmericanEnglish.TryGetIntFromWord(@string, out _) ? ValidationResult.ValidResult : new ValidationResult(false, Properties.Resources.validation_error_ComboBoxNotBip0039Word);
            }
            else
            {
                return new ValidationResult(false, Properties.Resources.error_Unimplemented);
            }
        }
    }
}
