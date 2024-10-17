/*
   YARA Rule Set
   Author: CERT-EE
   Date: 2024-10-14
   Identifier: tmpbUcAJ9
   Reference: https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_6ad91e399eca4253b5871954aa23cf63b6ea2338a9e5c57e18cead0ab4b485c1 {
   meta:
      description = "tmpbUcAJ9 - file 6ad91e399eca4253b5871954aa23cf63b6ea2338a9e5c57e18cead0ab4b485c1"
      author = "CERT-EE"
      reference = "https://cuckoo.cert.ee https://sandbox.pikker.ee https://cuckoo.ee"
      date = "2024-10-14"
      hash1 = "6ad91e399eca4253b5871954aa23cf63b6ea2338a9e5c57e18cead0ab4b485c1"
   strings:
      $s1 = "CreateProcess failed (%d)" fullword ascii
      $s2 = "cmd /c erase \"" fullword ascii
      $s3 = "<</DecodeParms<</Columns 4/Predictor 12>>/Encrypt 8 0 R/Filter/FlateDecode/ID[<2EF52842751B4E2E90118956E3D16F36><1D3013010F87AD4" ascii
      $s4 = "http://download.epac.to/staff.htm" fullword ascii
      $s5 = "<</DecodeParms<</Columns 4/Predictor 12>>/Encrypt 8 0 R/Filter/FlateDecode/ID[<2EF52842751B4E2E90118956E3D16F36><1D3013010F87AD4" ascii
      $s6 = "\\adobe_sl.exe" fullword ascii
      $s7 = "<</DecodeParms<</Columns 4/Predictor 12>>/Encrypt 8 0 R/Filter/FlateDecode/ID[<2EF52842751B4E2E90118956E3D16F36><1D3013010F87AD4" ascii
      $s8 = "Toftware\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" fullword ascii
      $s9 = "44444c" ascii /* reversed goodware string 'c44444' */
      $s10 = "4````````````" fullword ascii /* reversed goodware string '````````````4' */
      $s11 = "<</BitsPerComponent 8/ColorSpace/DeviceGray/DecodeParms<</BitsPerComponent 8/Colors 1/Columns 61>>/Filter/FlateDecode/Height 20/" ascii
      $s12 = "44444```````0^" fullword ascii /* hex encoded string 'DD@' */
      $s13 = "4```````````f^" fullword ascii /* hex encoded string 'O' */
      $s14 = "<</BitsPerComponent 8/ColorSpace 49 0 R/DecodeParms<</BitsPerComponent 8/Colors 3/Columns 61>>/Filter/FlateDecode/Height 20/Inte" ascii
      $s15 = "Hello@)!0" fullword ascii
      $s16 = "44444444````" fullword ascii /* hex encoded string 'DDDD' */
      $s17 = "<</ArtBox[27.582 17.832 765.07 590.998]/BleedBox[0.0 0.0 792.0 612.0]/Contents[12 0 R 13 0 R 14 0 R 15 0 R 16 0 R 17 0 R 18 0 R " ascii
      $s18 = "7444444444444444444//`4`" fullword ascii /* hex encoded string 'tDDDDDDDDD' */
      $s19 = "<</ArtBox[27.582 17.832 765.07 590.998]/BleedBox[0.0 0.0 792.0 612.0]/Contents[12 0 R 13 0 R 14 0 R 15 0 R 16 0 R 17 0 R 18 0 R " ascii
      $s20 = "<</BitsPerComponent 8/ColorSpace 49 0 R/DecodeParms<</BitsPerComponent 8/Colors 3/Columns 61>>/Filter/FlateDecode/Height 20/Inte" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

