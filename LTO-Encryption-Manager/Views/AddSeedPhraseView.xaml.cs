using System.Windows;
using System.Windows.Controls;
using uk.JohnCook.dotnet.LTOEncryptionManager.ViewModels;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.Views
{
	/// <summary>
	/// Interaction logic for AddSeedPhraseView.xaml
	/// </summary>
	public partial class AddSeedPhraseView : UserControl
    {
        public AddSeedPhraseView()
        {
            InitializeComponent();
        }

        public void ChangePassphrase(object sender, RoutedEventArgs e)
        {
            if (DataContext is not null && sender is not null)
            {
                ((AddSeedPhraseViewModel)DataContext).Passphrase = ((PasswordBox)sender).SecurePassword;
            }
        }
    }
}
