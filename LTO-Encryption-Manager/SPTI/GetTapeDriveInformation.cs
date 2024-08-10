using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using uk.JohnCook.dotnet.LTOEncryptionManager.Models;
using Windows.Win32.Foundation;

namespace uk.JohnCook.dotnet.LTOEncryptionManager.SPTI
{
    public partial class LTO
    {
        /// <summary>
        /// Call after getting a <see cref="SafeFileHandle"/> for a tape drive to populate some fields in a <see cref="TapeDrive"/> instance
        /// </summary>
        /// <param name="tapeDriveHandle">An open <see cref="SafeFileHandle"/> for a tape drive</param>
        /// <param name="tapeDrive">A <see cref="TapeDrive"/> instance</param>
        public static void GetTapeDriveInformation(TapeDrive tapeDrive)
        {
            HLOCAL storageDescriptorHeaderPtr = Windows.Win32.PInvoke.LocalAlloc(Windows.Win32.System.Memory.LOCAL_ALLOC_FLAGS.LPTR, (nuint)Marshal.SizeOf<Windows.Win32.System.Ioctl.STORAGE_DESCRIPTOR_HEADER>());
			HLOCAL adapterDescriptorPtr = (HLOCAL)IntPtr.Zero;
			HLOCAL deviceDescriptorPtr = (HLOCAL)IntPtr.Zero;
            Windows.Win32.System.Ioctl.STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader;
            NativeOverlapped overlapped;
            for (uint i = 0; i < 4; i++)
            {
                uint bufferSize = 0;
                uint returnedData = 0;

                Windows.Win32.System.Ioctl.STORAGE_PROPERTY_QUERY query = new()
                {
                    QueryType = Windows.Win32.System.Ioctl.STORAGE_QUERY_TYPE.PropertyStandardQuery
                };
                IntPtr buffer = IntPtr.Zero;
                switch (i)
                {
                    case 0:
                        query.PropertyId = Windows.Win32.System.Ioctl.STORAGE_PROPERTY_ID.StorageAdapterProperty;
                        bufferSize = (uint)Marshal.SizeOf<Windows.Win32.System.Ioctl.STORAGE_DESCRIPTOR_HEADER>();
                        buffer = storageDescriptorHeaderPtr;
                        break;
                    case 1:
                        query.PropertyId = Windows.Win32.System.Ioctl.STORAGE_PROPERTY_ID.StorageAdapterProperty;
                        storageDescriptorHeader = Marshal.PtrToStructure<Windows.Win32.System.Ioctl.STORAGE_DESCRIPTOR_HEADER>(storageDescriptorHeaderPtr);
                        bufferSize = storageDescriptorHeader.Size;
                        adapterDescriptorPtr = Windows.Win32.PInvoke.LocalAlloc(Windows.Win32.System.Memory.LOCAL_ALLOC_FLAGS.LPTR, bufferSize);
                        buffer = adapterDescriptorPtr;
                        break;
                    case 2:
                        query.PropertyId = Windows.Win32.System.Ioctl.STORAGE_PROPERTY_ID.StorageDeviceProperty;
                        bufferSize = (uint)Marshal.SizeOf<Windows.Win32.System.Ioctl.STORAGE_DESCRIPTOR_HEADER>();
                        buffer = storageDescriptorHeaderPtr;
                        break;
                    case 3:
                        query.PropertyId = Windows.Win32.System.Ioctl.STORAGE_PROPERTY_ID.StorageDeviceProperty;
                        storageDescriptorHeader = Marshal.PtrToStructure<Windows.Win32.System.Ioctl.STORAGE_DESCRIPTOR_HEADER>(storageDescriptorHeaderPtr);
                        bufferSize = storageDescriptorHeader.Size;
                        deviceDescriptorPtr = Windows.Win32.PInvoke.LocalAlloc(Windows.Win32.System.Memory.LOCAL_ALLOC_FLAGS.LPTR, bufferSize);
                        buffer = deviceDescriptorPtr;
                        break;
                }
                NativeMethods.RtlZeroMemory(buffer, (int)bufferSize);

                bool ok;
                unsafe
                {
                    ok = Windows.Win32.PInvoke.DeviceIoControl(tapeDrive.Handle,
                        Windows.Win32.PInvoke.IOCTL_STORAGE_QUERY_PROPERTY,
                        &query,
                        (uint)Marshal.SizeOf(query),
                        (void*)buffer,
                        bufferSize,
                        &returnedData,
                        &overlapped);
                }
                if (!ok)
                {
                    goto Cleanup;
                }
            }
            if (adapterDescriptorPtr != IntPtr.Zero)
            {
                Windows.Win32.System.Ioctl.STORAGE_ADAPTER_DESCRIPTOR adapterDescriptor = Marshal.PtrToStructure<Windows.Win32.System.Ioctl.STORAGE_ADAPTER_DESCRIPTOR>(adapterDescriptorPtr);
                tapeDrive.AlignmentMask = adapterDescriptor.AlignmentMask;
                tapeDrive.SrbType = adapterDescriptor.SrbType;
            }
            if (deviceDescriptorPtr != IntPtr.Zero)
            {
                Windows.Win32.System.Ioctl.STORAGE_DEVICE_DESCRIPTOR deviceDescriptor = Marshal.PtrToStructure<Windows.Win32.System.Ioctl.STORAGE_DEVICE_DESCRIPTOR>(deviceDescriptorPtr);
                //tapeDrive.StorageBusType = deviceDescriptor.BusType;
                if (deviceDescriptor.SerialNumberOffset != 0)
                {
                    IntPtr serialNumber = deviceDescriptorPtr;
                    serialNumber += (int)deviceDescriptor.SerialNumberOffset;
                    tapeDrive.SerialNumber = Marshal.PtrToStringAnsi(serialNumber) ?? string.Empty;
                }
            }
        Cleanup:
            Windows.Win32.PInvoke.LocalFree(adapterDescriptorPtr);
            Windows.Win32.PInvoke.LocalFree(deviceDescriptorPtr);
            Windows.Win32.PInvoke.LocalFree(storageDescriptorHeaderPtr);
        }
	}
}
