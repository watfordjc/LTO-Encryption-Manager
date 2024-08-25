using System;
using System.Windows.Forms;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.SecureDesktopWindows
{
    internal static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.SetHighDpiMode(HighDpiMode.SystemAware);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using RestoreSeedPhraseWindow window = new();
			Application.Run(window);
        }
    }
}
