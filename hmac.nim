#
#          Nim's Unofficial Library
#        (c) Copyright 2015 Huy Doan
#
#    See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements HMAC-SHA1 and HMC-MD5 hashing methods

import std/strutils
import checksums/[md5, sha1]
import nimSHA2 except toHex
import nimcrypto

type
  Keccak512Digest* = array[0..63, char]

proc hash_sha1*(s: string): Sha1Digest {.procvar.} = sha1.secureHash(s).Sha1Digest

proc hash_sha224*(s: string): SHA224Digest {.procvar.} = computeSHA224(s)

proc hash_sha256*(s: string): SHA256Digest {.procvar.} = computeSHA256(s)

proc hash_sha384*(s: string): SHA384Digest {.procvar.} = computeSHA384(s)

proc hash_sha512*(s: string): SHA512Digest {.procvar.} = computeSHA512(s)

proc hash_keccak512*(s: string): Keccak512Digest {.procvar.} = cast[Keccak512Digest](keccak512.digest(s))

proc hash_md5*(s: string): MD5Digest {.procvar.} = toMD5(s)

proc toHex*[T](x: T): string {.inline.} =
  when x is Sha1Digest:
    result = toLowerAscii($x.SecureHash)
  elif x is MD5Digest:
    result = toLowerAscii($x)
  else:
    result = toLowerAscii(nimSHA2.toHex(x))

template hmac_x[T](key, data: string, hash: proc(s: string): T, digest_size: int, block_size = 64, opad = 0x5c, ipad = 0x36) =
  var keyA: seq[uint8] = @[]
  var o_key_pad = newString(block_size + digest_size)
  var i_key_pad = newString(block_size)

  if key.len > block_size:
    for n in hash(key):
        keyA.add(n.uint8)
  else:
    for n in key:
       keyA.add(n.uint8)

  while keyA.len < block_size:
    keyA.add(0x00'u8)

  for i in 0..block_size-1:
    o_key_pad[i] = char(keyA[i].ord xor opad)
    i_key_pad[i] = char(keyA[i].ord xor ipad)
  var i = 0
  for x in hash(i_key_pad & data):
    o_key_pad[block_size + i] = char(x)
    inc(i)
  result = hash(o_key_pad)

proc hmac_sha1*(key, data: string, block_size = 64, opad = 0x5c, ipad = 0x36): Sha1Digest =
   hmac_x(key, data, hash_sha1, 20, block_size, opad, ipad)

proc hmac_sha224*(key, data: string, block_size = 64, opad = 0x5c, ipad = 0x36): Sha224Digest =
   hmac_x(key, data, hash_sha224, 32, block_size, opad, ipad)

proc hmac_sha256*(key, data: string, block_size = 64, opad = 0x5c, ipad = 0x36): SHA256Digest =
  hmac_x(key, data, hash_sha256, 32, block_size, opad, ipad)

proc hmac_sha384*(key, data: string, block_size = 64, opad = 0x5c, ipad = 0x36): SHA384Digest =
   hmac_x(key, data, hash_sha384, 64, block_size, opad, ipad)

proc hmac_sha512*(key, data: string, block_size = 128, opad = 0x5c, ipad = 0x36): SHA512Digest =
  hmac_x(key, data, hash_sha512, 64, block_size, opad, ipad)

proc hmac_keccak512*(key, data: string, block_size = 128, opad = 0x5c, ipad = 0x36): Keccak512Digest =
  result = cast[Keccak512Digest](sha3_512.hmac(key, data))

proc hmac_md5*(key, data: string): MD5Digest =
   hmac_x(key, data, hash_md5, 16)


when isMainModule:

  var result = toHex(hmac_sha1("key", "The quick brown fox jumps over the lazy dog"))
  echo result
  assert(result == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9","Incorrect hash")

  let longKey = "oiJkCotyEAcqEtbHAxwR0sj7Fl4CAT2xdT2oYJep6Wzes2umipBUzocVSwp7nL5ns4xDrPIBEBHKwIr3LlQLZmCw1wStOMSke9SDvQ2Gayj5ZGzvZ1T1uVyN4DcGenYd"
  result = toHex(hmac_sha1(longKey, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras ut nibh sit amet felis volutpat pellentesque eu at tellus. Etiam posuere justo eget mi porta porta."))
  echo result
  assert(result == "a0d87be75bb531af746ab7988e1e8058e7bc17f0","Incorrect hash")

  result = toHex(hmac_sha256("ubuntu", "Canonical to offer 5 years of support, but Snap packages mean latest features factor in."))
  echo result
  assert(result == "f53abed8001d0b7c8a64edc011854bded49e1ed55e5d5f5455b7b2ecf6506884", "Incorrect hash")

  result = toHex(hmac_sha256(longKey, "Nim (formerly known as \"Nimrod\") is a statically typed, imperative programming language that tries to give the programmer ultimate power without compromises on runtime efficiency. This means it focuses on compile-time mechanisms in all their various forms."))
  echo result
  assert(result == "8df227ae87aee5cad77c395eb4a589469421f4d23ced1a8e93270cd4c4fd9cbf", "Incorrect hash")

  result = toHex(hmac_md5("Jefe", "what do ya want for nothing?"))
  echo result
  assert(result == "750c783e6ab0b503eaa86e310a5db738","Incorrect hash")

  result = toHex(hmac_md5(longKey, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras ut nibh sit amet felis volutpat pellentesque eu at tellus. Etiam posuere justo eget mi porta porta."))
  echo result
  assert(result == "35acf8ac84d15ed02a4cd94331fc0aaa","Incorrect hash")

  result = toHex(hmac_sha512(longKey, "In cryptography, a keyed-hash message authentication code (HMAC) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authentication of a message, as with any MAC. Any cryptographic hash function, such as MD5 or SHA-1, may be used in the calculation of an HMAC"))
  echo result
  assert(result == "028f744134acb0917e750632133d37dd1da6260be730721a7e6ec44784cd08da653cfb484f4d03805048fe1ae9d881167d8198dfaae5a363358fd39283f9afb7", "Incorrect hash")

  result = toHex(hmac_keccak512(longKey, "In cryptography, a keyed-hash message authentication code (HMAC) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authentication of a message, as with any MAC. Any cryptographic hash function, such as MD5 or SHA-1, may be used in the calculation of an HMAC"))
  echo result
