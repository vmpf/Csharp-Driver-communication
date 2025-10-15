using System;
using System.Runtime.InteropServices;

internal static class NativeMethods
{
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped
    );

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    public const uint TH32CS_SNAPPROCESS = 0x00000002;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
}

public static class DriverCodes
{
    public const uint CODE_RW = 0x22201D58;
    public const uint CODE_BA = 0x22200048;
    public const uint CODE_GET_GUARDED_REGION = 0x22201CC8;
    public const int CODE_SECURITY = 0x52a1f65;
}

[StructLayout(LayoutKind.Sequential)]
public struct RW_STRUCT
{
    public int security;
    public int process_id;
    public ulong address;
    public ulong buffer;
    public ulong size;
    [MarshalAs(UnmanagedType.I1)]
    public bool write;
}

[StructLayout(LayoutKind.Sequential)]
public struct BA_STRUCT
{
    public int security;
    public int process_id;
    public ulong address;
}

[StructLayout(LayoutKind.Sequential)]
public struct GA_STRUCT
{
    public int security;
    public ulong address;
}

public class DriverCommunication
{
    private IntPtr _driverHandle = NativeMethods.INVALID_HANDLE_VALUE;
    public int ProcessId { get; private set; } = 0;

    private IntPtr StructureToPtr<T>(T structure)
    {
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(structure));
        Marshal.StructureToPtr(structure, ptr, false);
        return ptr;
    }

    private bool PerformIoControl(uint ioctlCode, IntPtr inBuffer, uint inSize, IntPtr outBuffer, uint outSize)
    {
        uint bytesReturned;
        return NativeMethods.DeviceIoControl(
            _driverHandle,
            ioctlCode,
            inBuffer,
            inSize,
            outBuffer,
            outSize,
            out bytesReturned,
            IntPtr.Zero
        );
    }

    public bool FindDriver()
    {
        _driverHandle = NativeMethods.CreateFile(
            "\\\\.\\IOCTLDrv",
            NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
            NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
            IntPtr.Zero,
            NativeMethods.OPEN_EXISTING,
            0,
            IntPtr.Zero
        );

        return _driverHandle != NativeMethods.INVALID_HANDLE_VALUE;
    }

    public void CloseDriver()
    {
        if (_driverHandle != NativeMethods.INVALID_HANDLE_VALUE)
        {
            NativeMethods.CloseHandle(_driverHandle);
            _driverHandle = NativeMethods.INVALID_HANDLE_VALUE;
        }
    }

    private void DataTransfer(ulong address, IntPtr bufferPtr, ulong size, bool write)
    {
        RW_STRUCT arguments = new RW_STRUCT
        {
            security = DriverCodes.CODE_SECURITY,
            address = address,
            buffer = (ulong)bufferPtr.ToInt64(),
            size = size,
            process_id = ProcessId,
            write = write
        };

        IntPtr inBufferPtr = StructureToPtr(arguments);
        try
        {
            PerformIoControl(DriverCodes.CODE_RW, inBufferPtr, (uint)Marshal.SizeOf<RW_STRUCT>(), IntPtr.Zero, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(inBufferPtr);
        }
    }

    public T Read<T>(ulong address) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        IntPtr bufferPtr = Marshal.AllocHGlobal(size);

        try
        {
            DataTransfer(address, bufferPtr, (ulong)size, false);

            if (typeof(T) == typeof(int))
            {
                return (T)(object)Marshal.ReadInt32(bufferPtr);
            }
            if (typeof(T) == typeof(uint))
            {
                return (T)(object)(uint)Marshal.ReadInt32(bufferPtr);
            }
            if (typeof(T) == typeof(short))
            {
                return (T)(object)Marshal.ReadInt16(bufferPtr);
            }
            if (typeof(T) == typeof(ushort))
            {
                return (T)(object)(ushort)Marshal.ReadInt16(bufferPtr);
            }
            if (typeof(T) == typeof(long))
            {
                // Direct read for long
                return (T)(object)Marshal.ReadInt64(bufferPtr);
            }
            if (typeof(T) == typeof(ulong))
            {
                return (T)(object)(ulong)Marshal.ReadInt64(bufferPtr);
            }
            if (typeof(T) == typeof(float))
            {
                int intValue = Marshal.ReadInt32(bufferPtr);
                return (T)(object)BitConverter.ToSingle(BitConverter.GetBytes(intValue), 0);
            }
            if (typeof(T) == typeof(double))
            {
                long longValue = Marshal.ReadInt64(bufferPtr);
                return (T)(object)BitConverter.ToDouble(BitConverter.GetBytes(longValue), 0);
            }
            return Marshal.PtrToStructure<T>(bufferPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(bufferPtr);
        }
    }

    public void Write<T>(ulong address, T value) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        IntPtr bufferPtr = Marshal.AllocHGlobal(size);

        try
        {
            if (typeof(T) == typeof(int))
            {
                Marshal.WriteInt32(bufferPtr, (int)(object)value);
            }
            else if (typeof(T) == typeof(uint))
            {
                Marshal.WriteInt32(bufferPtr, (int)(uint)(object)value);
            }
            else if (typeof(T) == typeof(short))
            {
                Marshal.WriteInt16(bufferPtr, (short)(object)value);
            }
            else if (typeof(T) == typeof(ushort))
            {
                Marshal.WriteInt16(bufferPtr, (short)(ushort)(object)value);
            }
            else if (typeof(T) == typeof(long) || typeof(T) == typeof(ulong))
            {
                Marshal.WriteInt64(bufferPtr, (long)(object)value);
            }
            else if (typeof(T) == typeof(float))
            {
                byte[] bytes = BitConverter.GetBytes((float)(object)value);
                Marshal.Copy(bytes, 0, bufferPtr, size);
            }
            else if (typeof(T) == typeof(double))
            {
                byte[] bytes = BitConverter.GetBytes((double)(object)value);
                Marshal.Copy(bytes, 0, bufferPtr, size);
            }
            else
            {
                Marshal.StructureToPtr(value, bufferPtr, false);
            }

            DataTransfer(address, bufferPtr, (ulong)size, true);
        }
        finally
        {
            Marshal.FreeHGlobal(bufferPtr);
        }
    }

    public ulong FindImage()
    {
        ulong imageAddress = 0;
        int size = Marshal.SizeOf<ulong>();
        IntPtr outBufferPtr = Marshal.AllocHGlobal(size);

        BA_STRUCT arguments = new BA_STRUCT
        {
            security = DriverCodes.CODE_SECURITY,
            process_id = ProcessId,
            address = (ulong)outBufferPtr.ToInt64()
        };

        IntPtr inBufferPtr = StructureToPtr(arguments);

        try
        {
            PerformIoControl(DriverCodes.CODE_BA, inBufferPtr, (uint)Marshal.SizeOf<BA_STRUCT>(), IntPtr.Zero, 0);
            imageAddress = (ulong)Marshal.PtrToStructure<ulong>(outBufferPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(inBufferPtr);
            Marshal.FreeHGlobal(outBufferPtr);
        }

        return imageAddress;
    }

    public ulong GetGuardedRegion()
    {
        ulong guardedAddress = 0;
        int size = Marshal.SizeOf<ulong>();
        IntPtr outBufferPtr = Marshal.AllocHGlobal(size);

        GA_STRUCT arguments = new GA_STRUCT
        {
            security = DriverCodes.CODE_SECURITY,
            address = (ulong)outBufferPtr.ToInt64()
        };

        IntPtr inBufferPtr = StructureToPtr(arguments);

        try
        {
            PerformIoControl(DriverCodes.CODE_GET_GUARDED_REGION, inBufferPtr, (uint)Marshal.SizeOf<GA_STRUCT>(), IntPtr.Zero, 0);
            guardedAddress = (ulong)Marshal.PtrToStructure<ulong>(outBufferPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(inBufferPtr);
            Marshal.FreeHGlobal(outBufferPtr);
        }

        return guardedAddress;
    }

    public int FindProcess(string processName)
    {
        IntPtr hSnapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);

        if (hSnapshot == NativeMethods.INVALID_HANDLE_VALUE)
        {
            return 0;
        }

        NativeMethods.PROCESSENTRY32 pe32 = new NativeMethods.PROCESSENTRY32();
        pe32.dwSize = (uint)Marshal.SizeOf(pe32);

        if (!NativeMethods.Process32First(hSnapshot, ref pe32))
        {
            NativeMethods.CloseHandle(hSnapshot);
            return 0;
        }

        do
        {
            if (string.Compare(pe32.szExeFile, processName, true) == 0)
            {
                NativeMethods.CloseHandle(hSnapshot);
                ProcessId = (int)pe32.th32ProcessID;
                return ProcessId;
            }
        } while (NativeMethods.Process32Next(hSnapshot, ref pe32));

        NativeMethods.CloseHandle(hSnapshot);
        return 0;
    }
}
