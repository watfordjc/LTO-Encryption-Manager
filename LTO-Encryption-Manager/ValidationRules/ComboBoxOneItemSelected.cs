using System.Globalization;
using System.Windows.Controls;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.ValidationRules
{
    public class ComboBoxOneItemSelected : ValidationRule
    {
        public override ValidationResult Validate(object value, CultureInfo cultureInfo)
        {
            if (value == null)
            {
                return new ValidationResult(false, Properties.Resources.validation_error_ComboBoxOneItemSelected);
            }
            return ValidationResult.ValidResult;
        }
    }
}
