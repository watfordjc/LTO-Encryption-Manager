using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using uk.JohnCook.dotnet.LTOEncryptionManager.Models;
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
            if (DataContext != null)
            {
                ((AddSeedPhraseViewModel)DataContext).Passphrase = ((PasswordBox)sender).SecurePassword;
            }
        }
    }
}
