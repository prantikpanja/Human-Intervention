/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmpsdi9S4
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_6b3b6ae4dd02cbd4a01075f0a3d92412c338368e281fbb7f413ebcb9d5a79990 {
   meta:
      description = "tmpsdi9S4 - file 6b3b6ae4dd02cbd4a01075f0a3d92412c338368e281fbb7f413ebcb9d5a79990"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "6b3b6ae4dd02cbd4a01075f0a3d92412c338368e281fbb7f413ebcb9d5a79990"
   strings:
      $x1 = "Process cmd.exe exited!" fullword ascii
      $s2 = "NTLMSVC.dll" fullword ascii
      $s3 = "NTLMSVC.DLL" fullword wide
      $s4 = "list process failed!" fullword ascii
      $s5 = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" fullword ascii
      $s6 = "geturl" fullword ascii
      $s7 = "pidrun" fullword ascii
      $s8 = "Start shell first." fullword ascii
      $s9 = "Shell started fail!" fullword ascii
      $s10 = "GetFileAttributes Error code: %d" fullword ascii
      $s11 = "%ComSpec%" fullword ascii
      $s12 = "Service is running already!" fullword ascii
      $s13 = "list service failed!" fullword ascii
      $s14 = "Proxy-Connection:Keep-Alive" fullword ascii
      $s15 = "Service still running!" fullword ascii
      $s16 = "OpenT failed with %d!" fullword ascii
      $s17 = "Create failed with %d!" fullword ascii
      $s18 = "StartService failed!" fullword ascii
      $s19 = "OpenService failed!" fullword ascii
      $s20 = "ControlService failed!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and 4 of them
}

