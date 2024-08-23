using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Security;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.ViewModels
{
	public static class SecureBoot
    {
        public static bool IsEnabled()
        {
            string key = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State";
            string subkey = @"UEFISecureBootEnabled";
            try
            {
                object? value = Registry.GetValue(key, subkey, 0);
                return value is not null && (int)value != 0;
			}
            catch (Exception e) when
            (e is SecurityException || e is IOException || e is ArgumentException)
            {
                Trace.WriteLine($"Exception: {e.Message}");
                return false;
            }
        }
    }
}
