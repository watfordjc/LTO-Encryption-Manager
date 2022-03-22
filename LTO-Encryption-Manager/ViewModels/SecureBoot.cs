using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
                if (value is null || (int)value == 0)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            catch (Exception e)
            {
                Trace.WriteLine($"Exception: {e.Message}");
                return false;
            }
        }
    }
}
