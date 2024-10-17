/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmp9HaSqQ
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_6bb764f3a5ca57f9bcc72aa0c34dab64e870e22c6400f6b3f62d5986104dc68f {
   meta:
      description = "tmp9HaSqQ - file 6bb764f3a5ca57f9bcc72aa0c34dab64e870e22c6400f6b3f62d5986104dc68f"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "6bb764f3a5ca57f9bcc72aa0c34dab64e870e22c6400f6b3f62d5986104dc68f"
   strings:
      $x1 = "Process cmd.exe exited!" fullword ascii
      $s2 = "list process failed!" fullword ascii
      $s3 = "error no RegCreateKeyEx %s" fullword ascii
      $s4 = "geturl" fullword ascii
      $s5 = "pidrun" fullword ascii
      $s6 = "Start shell first." fullword ascii
      $s7 = "GetFileAttributes Error code: %d" fullword ascii
      $s8 = "Shell started fail!" fullword ascii
      $s9 = "%ComSpec%" fullword ascii
      $s10 = "OpenP failed with %d!" fullword ascii
      $s11 = "Service still running!" fullword ascii
      $s12 = "OpenService failed!" fullword ascii
      $s13 = "StartService failed!" fullword ascii
      $s14 = "Service is running already!" fullword ascii
      $s15 = "OpenT failed with %d!" fullword ascii
      $s16 = "Create failed with %d!" fullword ascii
      $s17 = "ControlService failed!" fullword ascii
      $s18 = "Proxy-Connection:Keep-Alive" fullword ascii
      $s19 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\EXPlorer\\Run" fullword ascii
      $s20 = "Failed with %d!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      1 of ($x*) and 4 of them
}

