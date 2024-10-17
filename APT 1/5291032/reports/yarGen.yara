/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmpZSRTA1
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_1b3ee0274ae0ac0b83dba7f95f00e2381a5d3596d136eb1fac842a07d8d25262 {
   meta:
      description = "tmpZSRTA1 - file 1b3ee0274ae0ac0b83dba7f95f00e2381a5d3596d136eb1fac842a07d8d25262"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "1b3ee0274ae0ac0b83dba7f95f00e2381a5d3596d136eb1fac842a07d8d25262"
   strings:
      $x1 = "Process cmd.exe exited!" fullword ascii
      $s2 = "list process failed!" fullword ascii
      $s3 = "geturl" fullword ascii
      $s4 = "pidrun" fullword ascii
      $s5 = "GetFileAttributes Error code: %d" fullword ascii
      $s6 = "Start shell first." fullword ascii
      $s7 = "Shell started fail!" fullword ascii
      $s8 = "%ComSpec%" fullword ascii
      $s9 = "Service still running!" fullword ascii
      $s10 = "Create failed with %d!" fullword ascii
      $s11 = "list service failed!" fullword ascii
      $s12 = "Service is running already!" fullword ascii
      $s13 = "OpenP failed with %d!" fullword ascii
      $s14 = "StartService failed!" fullword ascii
      $s15 = "OpenT failed with %d!" fullword ascii
      $s16 = "ControlService failed!" fullword ascii
      $s17 = "OpenService failed!" fullword ascii
      $s18 = "Proxy-Connection:Keep-Alive" fullword ascii
      $s19 = "GetUrl URL FileName" fullword ascii
      $s20 = "Shell started successfully!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and 4 of them
}

