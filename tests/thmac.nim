import unittest, strutils, sha1, hmac

proc hexToString(s: string): string =
  var pair: string
  for ch in s:
    pair.add(ch)
    if pair.len == 2:
      result &= fromHex[uint8](pair).char
      pair = ""


suite "HMAC":

  test "SHA1 (from https://tools.ietf.org/html/rfc2202 section 3)":
    var key: string
    var data: string
    var expectedDigest: string
    var rcvdDigest: string

    # test case 1
    key = hexToString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    # key length of 20
    data = "Hi There"
    # data of length 8
    expectedDigest = "b617318655057264e28bc0b6fb378c8ef146be00"
    rcvdDigest = toHex(hmac_sha1(key, data))
    check rcvdDigest == expectedDigest

    # test case 2
    key = "Jefe"
    # key length of 4
    data = "what do ya want for nothing?"
    # data of length 28
    expectedDigest = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    rcvdDigest = toHex(hmac_sha1(key, data))
    check rcvdDigest == expectedDigest

    # test case 3
    key = hexToString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    # key length of 20
    data = "dd".hexToString.repeat(50)
    # data of length 50
    expectedDigest = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    rcvdDigest = toHex(hmac_sha1(key, data))
    check rcvdDigest == expectedDigest

    # test case 4
    key = hexToString("0102030405060708090a0b0c0d0e0f10111213141516171819")
    # key length of 25
    data = "cd".hexToString.repeat(50)
    # data of length 50
    expectedDigest = "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
    rcvdDigest = toHex(hmac_sha1(key, data))
    check rcvdDigest == expectedDigest

    # test case 5
    key = hexToString("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
    # key length of 20
    data = "Test With Truncation"
    # data of length 20
    expectedDigest = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
    rcvdDigest = toHex(hmac_sha1(key, data))
    check rcvdDigest == expectedDigest

    # test case 6
    key = "aa".hexToString.repeat(80)
    # key length of 80
    data = "Test Using Larger Than Block-Size Key - Hash Key First"
    # data of length 54
    expectedDigest = "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    rcvdDigest = toHex(hmac_sha1(key, data))
    check rcvdDigest == expectedDigest

    # test case 7
    key = "aa".hexToString.repeat(80)
    # key length of 80
    data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    # data of length 73
    expectedDigest = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    rcvdDigest = toHex(hmac_sha1(key, data))
    check rcvdDigest == expectedDigest

  test "SHA256":
    let longKey = "oiJkCotyEAcqEtbHAxwR0sj7Fl4CAT2xdT2oYJep6Wzes2umipBUzocVSwp7nL5ns4xDrPIBEBHKwIr3LlQLZmCw1wStOMSke9SDvQ2Gayj5ZGzvZ1T1uVyN4DcGenYd"
    var rcvdDigest: string

    rcvdDigest = toHex(hmac_sha256("ubuntu", "Canonical to offer 5 years of support, but Snap packages mean latest features factor in."))
    check rcvdDigest == "f53abed8001d0b7c8a64edc011854bded49e1ed55e5d5f5455b7b2ecf6506884"

    rcvdDigest = toHex(hmac_sha256(longKey, "Nim (formerly known as \"Nimrod\") is a statically typed, imperative programming language that tries to give the programmer ultimate power without compromises on runtime efficiency. This means it focuses on compile-time mechanisms in all their various forms."))
    check rcvdDigest == "8df227ae87aee5cad77c395eb4a589469421f4d23ced1a8e93270cd4c4fd9cbf"


  test "SHA256":
    let longKey = "oiJkCotyEAcqEtbHAxwR0sj7Fl4CAT2xdT2oYJep6Wzes2umipBUzocVSwp7nL5ns4xDrPIBEBHKwIr3LlQLZmCw1wStOMSke9SDvQ2Gayj5ZGzvZ1T1uVyN4DcGenYd"
    var rcvdDigest: string

    rcvdDigest = toHex(hmac_sha512(longKey, "In cryptography, a keyed-hash message authentication code (HMAC) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authentication of a message, as with any MAC. Any cryptographic hash function, such as MD5 or SHA-1, may be used in the calculation of an HMAC"))
    check rcvdDigest == "028f744134acb0917e750632133d37dd1da6260be730721a7e6ec44784cd08da653cfb484f4d03805048fe1ae9d881167d8198dfaae5a363358fd39283f9afb7"

  test "MD5":
    let longKey = "oiJkCotyEAcqEtbHAxwR0sj7Fl4CAT2xdT2oYJep6Wzes2umipBUzocVSwp7nL5ns4xDrPIBEBHKwIr3LlQLZmCw1wStOMSke9SDvQ2Gayj5ZGzvZ1T1uVyN4DcGenYd"
    var rcvdDigest: string

    rcvdDigest = toHex(hmac_md5("Jefe", "what do ya want for nothing?"))
    check rcvdDigest == "750c783e6ab0b503eaa86e310a5db738"

    rcvdDigest = toHex(hmac_md5(longKey, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras ut nibh sit amet felis volutpat pellentesque eu at tellus. Etiam posuere justo eget mi porta porta."))
    check rcvdDigest == "35acf8ac84d15ed02a4cd94331fc0aaa"
