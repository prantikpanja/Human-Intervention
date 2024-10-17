/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmp1NuzS9
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_1d1a290668c7331317309eb7336e9df94e0b034a175bb8d477cb46b7dfaf26f6 {
   meta:
      description = "tmp1NuzS9 - file 1d1a290668c7331317309eb7336e9df94e0b034a175bb8d477cb46b7dfaf26f6"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "1d1a290668c7331317309eb7336e9df94e0b034a175bb8d477cb46b7dfaf26f6"
   strings:
      $x1 = "\\cmd.exe /c " fullword ascii
      $s2 = "ActiveX.exe" fullword wide
      $s3 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0)" fullword ascii
      $s4 = "  !!!!!" fullword ascii
      $s5 = "thequickbrownfxjmpsvalzydg" fullword ascii
      $s6 = "xxxxx: %d!" fullword ascii
      $s7 = "Dcryption Error! Invalid Character '%c'." fullword ascii
      $s8 = "jejxjej.jdjm" fullword ascii
      $s9 = "MicroSoft Corporation" fullword wide
      $s10 = "MicroSoft Corporation ActiveX" fullword wide
      $s11 = "%s\\%c%c%c%c%c%c%c" fullword ascii
      $s12 = "ActiveX" fullword wide /* Goodware String - occured 21 times */
      $s13 = "COMSPEC" fullword ascii /* Goodware String - occured 247 times */
      $s14 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* Goodware String - occured 903 times */
      $s15 = "  xxxxx: %d" fullword ascii
      $s16 = "`1234567890-=~!@#$^&*()_+qwertyuiop[]QWERTYUIOP|asdfghjkl;'ASDFGHJKL:zxcvbnm,./ZXCVBNM<>?" fullword ascii
      $s17 = "Copyright ? 2008" fullword wide
      $s18 = "T$8VRh" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "L$4PQVVVj" fullword ascii
      $s20 = "D$<SUVWh" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      1 of ($x*) and 4 of them
}

