/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmpqCKx8A
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_6ad0190caa69dc0d662088f86aab7ee3355e788b1196552dd7487f6052150d8e {
   meta:
      description = "tmpqCKx8A - file 6ad0190caa69dc0d662088f86aab7ee3355e788b1196552dd7487f6052150d8e"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "6ad0190caa69dc0d662088f86aab7ee3355e788b1196552dd7487f6052150d8e"
   strings:
      $x1 = "Process cmd.exe exited!" fullword ascii
      $s2 = "list process failed!" fullword ascii
      $s3 = "geturl" fullword ascii
      $s4 = "pidrun" fullword ascii
      $s5 = "Start shell first." fullword ascii
      $s6 = "GetFileAttributes Error code: %d" fullword ascii
      $s7 = "Shell started fail!" fullword ascii
      $s8 = "%ComSpec%" fullword ascii
      $s9 = "Service still running!" fullword ascii
      $s10 = "StartService failed!" fullword ascii
      $s11 = "OpenP failed with %d!" fullword ascii
      $s12 = "OpenT failed with %d!" fullword ascii
      $s13 = "list service failed!" fullword ascii
      $s14 = "Proxy-Connection:Keep-Alive" fullword ascii
      $s15 = "OpenService failed!" fullword ascii
      $s16 = "Service is running already!" fullword ascii
      $s17 = "ControlService failed!" fullword ascii
      $s18 = "Create failed with %d!" fullword ascii
      $s19 = "Failed with %d!" fullword ascii
      $s20 = "Shell started successfully!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      1 of ($x*) and 4 of them
}

