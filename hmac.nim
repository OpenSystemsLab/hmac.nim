from sha1 import SHA1Digest, compute
from md5 import MD5Digest, toMD5

proc hmac_sha1*(key, data: string, block_size = 64, opad = 0x5c, ipad = 0x36): SHA1Digest =
  var keyA, o_key_pad: seq[uint8] = @[]
  var i_key_pad = newString(block_size)

  if key.len > block_size:
    for n in compute(key):
      keyA.add(n)
  else:
    for n in key:
      keyA.add(n.uint8)

  while keyA.len < block_size:
    keyA.add(0x00)

  for i in 0..block_size-1:
    o_key_pad.add uint8(keyA[i].ord xor opad)
    i_key_pad[i] = char(keyA[i].ord xor ipad)

  for i in compute(i_key_pad & data):
    o_key_pad.add(i)
  result = compute(o_key_pad)

proc hmac_md5*(key, data: string): MD5Digest =
  var keyA: seq[uint8] = @[]
  var o_key_pad = newString(80)
  var i_key_pad = newString(64)

  if key.len > 64:
    for n in toMD5(key):
      keyA.add(n)
  else:
    for n in key:
      keyA.add(n.uint8)

  while keyA.len < 64:
    keyA.add(0x00)

  for i in 0..63:
    o_key_pad[i] = char(keyA[i].ord xor 0x5c)
    i_key_pad[i] = char(keyA[i].ord xor 0x36)

  let inner_digest = toMD5(i_key_pad & data)
  for i in 0..inner_digest.len-1:
    o_key_pad[64+i] = char(inner_digest[i])
  result = toMD5(o_key_pad);


when isMainModule:
  from sha1 import toHex
  from md5 import `$`

  var result = hmac_sha1("key", "The quick brown fox jumps over the lazy dog").toHex()
  echo result
  assert(result == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9","Incorrect hash")

  let longKey = "oiJkCotyEAcqEtbHAxwR0sj7Fl4CAT2xdT2oYJep6Wzes2umipBUzocVSwp7nL5ns4xDrPIBEBHKwIr3LlQLZmCw1wStOMSke9SDvQ2Gayj5ZGzvZ1T1uVyN4DcGenYd"
  result = hmac_sha1(longKey, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras ut nibh sit amet felis volutpat pellentesque eu at tellus. Etiam posuere justo eget mi porta porta.").toHex()
  echo result
  assert(result == "a0d87be75bb531af746ab7988e1e8058e7bc17f0","Incorrect hash")

  result = $hmac_md5("Jefe", "what do ya want for nothing?")
  echo result
  assert(result == "750c783e6ab0b503eaa86e310a5db738","Incorrect hash")

  result = $hmac_md5(longKey, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras ut nibh sit amet felis volutpat pellentesque eu at tellus. Etiam posuere justo eget mi porta porta.")
  echo result
  assert(result == "35acf8ac84d15ed02a4cd94331fc0aaa","Incorrect hash")
