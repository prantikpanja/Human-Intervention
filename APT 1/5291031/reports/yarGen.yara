/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmpNPfTUL
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_1a6a112fa17b49e57ce20abf787054d86f7ec0b52c7728c869db2ff287708e74 {
   meta:
      description = "tmpNPfTUL - file 1a6a112fa17b49e57ce20abf787054d86f7ec0b52c7728c869db2ff287708e74"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "1a6a112fa17b49e57ce20abf787054d86f7ec0b52c7728c869db2ff287708e74"
   strings:
      $x1 = "E:\\Work\\2007Code\\password and token\\SamDump\\bkhive-1.1.0\\Debug\\bkhive.pdb" fullword ascii
      $s2 = "Error reading ControlSet: _RegOpenKey" fullword ascii
      $s3 = "Error reading hive root key" fullword ascii
      $s4 = "bkhive systemhive keyfile" fullword ascii
      $s5 = "Error reading ControlSet: _RegQueryValue" fullword ascii
      $s6 = "Error accessing key %s" fullword ascii
      $s7 = "Root Key : %s" fullword ascii
      $s8 = "Error opening hive file %s" fullword ascii
      $s9 = " Data: <%s> %s" fullword ascii
      $s10 = "http://www.objectif-securite.ch" fullword ascii
      $s11 = "Bootkey: " fullword ascii
      $s12 = "original author: ncuomo@studenti.unina.it" fullword ascii
      $s13 = "Default ControlSet: %03d" fullword ascii
      $s14 = "Client hook allocation failure." fullword ascii /* Goodware String - occured 14 times */
      $s15 = "Object dump complete." fullword ascii /* Goodware String - occured 14 times */
      $s16 = "Default" fullword ascii /* Goodware String - occured 912 times */
      $s17 = "mbtowc.c" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "MB_CUR_MAX == 1 || MB_CUR_MAX == 2" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "flag == 0 || flag == 1" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "%s\\ControlSet%03d\\Control\\Lsa\\" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      1 of ($x*) and 4 of them
}

