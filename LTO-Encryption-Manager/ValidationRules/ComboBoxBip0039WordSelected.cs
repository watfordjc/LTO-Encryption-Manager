using System.Globalization;
using System.Windows.Controls;
using uk.JohnCook.dotnet.LTOEncryptionManager.ImprovementProposals.BIP39Dictionaries;

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
                return AmericanEnglish.TryGetIntFromWord(@string, out _) ? ValidationResult.ValidResult : new ValidationResult(false, Properties.Resources.validation_error_ComboBoxNotBip0039Word);
            }
            else
            {
                return new ValidationResult(false, Properties.Resources.error_Unimplemented);
            }
        }
    }
}
