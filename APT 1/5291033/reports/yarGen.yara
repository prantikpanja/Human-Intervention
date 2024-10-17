/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmpVgxXm_
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_1cc1a6f131617e0a15380e327e96d903ba4512dca45b63b9a456751495ede76c {
   meta:
      description = "tmpVgxXm_ - file 1cc1a6f131617e0a15380e327e96d903ba4512dca45b63b9a456751495ede76c"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "1cc1a6f131617e0a15380e327e96d903ba4512dca45b63b9a456751495ede76c"
   strings:
      $s1 = " /a > nul" fullword ascii
      $s2 = "The last Error Code is" fullword ascii
      $s3 = "SeDebugPrivilege" fullword ascii /* Goodware String - occured 141 times */
      $s4 = "COMSPEC" fullword ascii /* Goodware String - occured 247 times */
      $s5 = "SVWj?3" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "PWhA8@" fullword ascii
      $s7 = "pbZ5s*" fullword ascii
      $s8 = "/c del " fullword ascii
      $s9 = "HHtvHt" fullword ascii /* Goodware String - occured 4 times */
      $s10 = "-%X/df" fullword ascii
      $s11 = "j@h`A@" fullword ascii
      $s12 = "j0h(B@" fullword ascii
      $s13 = "SUVWj@" fullword ascii /* Goodware String - occured 4 times */
      $s14 = "PWhU.@" fullword ascii
      $s15 = "j@h A@" fullword ascii
      $s16 = "Ih8TBX" fullword ascii
      $s17 = "t*SWPj" fullword ascii
      $s18 = "$VWhLP@" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

