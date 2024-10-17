/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmpq_HqjT
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_1d0d00c76353c8a1d2e33af602238244f0e0417193d7f65cfca4f4b576107071 {
   meta:
      description = "tmpq_HqjT - file 1d0d00c76353c8a1d2e33af602238244f0e0417193d7f65cfca4f4b576107071"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "1d0d00c76353c8a1d2e33af602238244f0e0417193d7f65cfca4f4b576107071"
   strings:
      $x1 = "\\cmd.exe /c " fullword ascii
      $s2 = "temp.tmp" fullword ascii
      $s3 = "name=WinUpdater&userid=%04d&other=%c%s" fullword ascii
      $s4 = "CreateOnceCmd Error: %d!" fullword ascii
      $s5 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0)" fullword ascii
      $s6 = "Connection Coming!" fullword ascii
      $s7 = "CreateFile fail. Error = %d." fullword ascii
      $s8 = "InternetOpen fail. Error = %d." fullword ascii
      $s9 = "HttpOpenRequest fail. Error = %d." fullword ascii
      $s10 = "HttpSendRequestEx fail. Error = %d." fullword ascii
      $s11 = "InternetConnect fail. Error = %d." fullword ascii
      $s12 = "httpput " fullword ascii
      $s13 = "thequickbrownfxjmpsvalzydg" fullword ascii
      $s14 = "jpghttp://" fullword ascii
      $s15 = "COMSPEC" fullword ascii /* Goodware String - occured 247 times */
      $s16 = "Rich-kF" fullword ascii
      $s17 = "\\cmd.exe" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "(GovdJlDSmdDhyB9XxLHmlHKpoV@J6gvN07#Y=G0O(GovdJlDSmdDhyB9XxLHmlHKpoWuI5g#QnJDaAfme" fullword wide
      $s19 = "  Wait for %02d minute(s)..." fullword ascii
      $s20 = "D$@SPh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      1 of ($x*) and 4 of them
}

