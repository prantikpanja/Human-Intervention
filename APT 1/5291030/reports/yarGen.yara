/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmp7I3PNk
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_0fbb47373b8bbefdfd9377dc26b6418d2738e6f688562885f4d2a1a049e4948e {
   meta:
      description = "tmp7I3PNk - file 0fbb47373b8bbefdfd9377dc26b6418d2738e6f688562885f4d2a1a049e4948e"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "0fbb47373b8bbefdfd9377dc26b6418d2738e6f688562885f4d2a1a049e4948e"
   strings:
      $s1 = "dW5zdXBwb3J0" fullword ascii /* base64 encoded string 'unsupport' */
      $s2 = "70.88.223.225" fullword ascii
      $s3 = "D7 /INW" fullword ascii
      $s4 = "Update" fullword wide /* Goodware String - occured 303 times */
      $s5 = "ysrqpnlj?i=" fullword ascii
      $s6 = "++)'HG&FEDBA@\\[" fullword ascii
      $s7 = "bb`_ywwttus" fullword ascii
      $s8 = "cXVpdA==" fullword ascii
      $s9 = "aSSQRMONKLef|{zz" fullword ascii
      $s10 = "|jxaLjS<fN7bJ2`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0`H0" fullword ascii
      $s11 = "+Windows+NT+5.521" fullword ascii
      $s12 = "pppp&&''" fullword ascii
      $s13 = "ZQO2PLKJ`_lk" fullword ascii
      $s14 = "2211/U.RTONPL-ffJJdcb" fullword ascii
      $s15 = "1234567890123456" ascii /* Goodware String - occured 1 times */
      $s16 = "0{PQMJIFCB>" fullword ascii
      $s17 = "kWzcNr[EjS<`H0" fullword ascii
      $s18 = "~55Z.*Hh}^s" fullword ascii
      $s19 = "<Dt,<St" fullword ascii
      $s20 = "ppp&''" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

