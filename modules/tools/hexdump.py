#!/usr/bin/python3

import sys
import binascii


PY3K = sys.version_info >= (3, 0)

def chunks(seq, size): 
  '''Cut sequence into chunks of given size. If `seq` length is 
     not divisible by `size` without reminder, last chunk will 
     have length less than size. 

     >>> list( chunks([1,2,3,4,5,6,7], 3) ) 
     [[1, 2, 3], [4, 5, 6], [7]] 
  ''' 
  d, m = divmod(len(seq), size)
  for i in range(d):
    yield seq[i*size:(i+1)*size]
  if m: 
    yield seq[d*size:] 


def hexdump(data):
  '''
  Print binary data in the hex dump text format:

  0000 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

    [x] data argument as a binary string
    [ ] data argument as an iterable
  '''
  if PY3K and type(data) == str:
    raise TypeError('Abstract unicode data (expected bytes)')

  line = ''
  for addr, d in enumerate(chunks(data, 16)):
    # 0000000000:
    line = '%004X ' % (addr*16)
    # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
    dump = binascii.hexlify(d).decode('ascii').upper()
    dump = ' '.join(chunks(dump, 2))

    line += dump[:8*3]
    if len(d) > 8:  # insert separator if needed
      line += ' ' + dump[8*3:]
    # ................
    # calculate indentation, which may be different for the last line
    pad = 2
    if len(d) < 16:
      pad += 3*(16 - len(d))
    if len(d) <= 8:
      pad += 1
    line += ' '*pad

    for byte in d:
      # printable ASCII range 0x20 to 0x7E
      if not PY3K:
        byte = ord(byte)
      if 0x20 <= byte <= 0x7E:
        line += chr(byte)
      else:
        line += '.'
    print(line)
