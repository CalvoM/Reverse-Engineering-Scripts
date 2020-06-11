"""
U-boot header fields and size
| POS | SIZE | TYPE       | ID 
|  0  |  4   | 27051956   | Magic No.
|  4  |  4   | u4be       | Header CRC
|  8  |  4   | u4be       | timestamp
| 12  |  4   | u4be       | image_len
| 16  |  4   | u4be       | load_address
| 20  |  4   | u4be       | entry_address
| 24  |  4   | u4be       | data_crc
| 28  |  1   | u1-uImageOs| os_type
| 29  |  1   | u1-uImgArch| architecture
| 30  |  1   | u1-uImgType| image_type
| 31  |  1   | u1-uImgComp| compression_type
| 32  |  1   | str(UTF-8) | name
"""

import struct
import sys
import binascii
import datetime
import yaml
import binwalk
import os
#* Please supply the extracted header file some images do not have the header as first portion

file_name = sys.argv[1]
pack_fmt = "!I" #Prevent unexpected negative numbers e.g for CRC
scripts_folder = os.path.dirname(os.path.abspath(__file__)) #Just better reference
fields_path = scripts_folder+"/field.yaml"
with open(fields_path) as yf:
    fields = yaml.load(yf,Loader=yaml.FullLoader)

arch = fields['enums']['uimage_arch']
os = fields['enums']['uimage_os']
compression = fields['enums']['uimage_comp']
image = fields['enums']['uimage_type']
#Get header details
with open(file_name,'rb') as f:
    uImgHeader = f.read(0x40)
    magic_number, = struct.unpack(pack_fmt, uImgHeader[0:4])
    header_crc, = struct.unpack(pack_fmt, uImgHeader[4:8])
    timestamp, = struct.unpack(pack_fmt, uImgHeader[8:12])
    image_len, = struct.unpack(pack_fmt, uImgHeader[12:16])
    load_addr, = struct.unpack(pack_fmt, uImgHeader[16:20])
    entry_addr, = struct.unpack(pack_fmt, uImgHeader[20:24])
    data_crc, = struct.unpack(pack_fmt, uImgHeader[24:28])
    pack_fmt = "!b"
    os_type, = struct.unpack(pack_fmt, uImgHeader[28:29])
    architecture, = struct.unpack(pack_fmt, uImgHeader[29:30])
    image_type, = struct.unpack(pack_fmt, uImgHeader[30:31])
    compression_type ,= struct.unpack(pack_fmt, uImgHeader[31:32])
    pack_fmt = "!32s"
    image_name, = struct.unpack(pack_fmt, uImgHeader[32:64])

#confirm the CRC-32
copy_img = list(uImgHeader)
copy_img[4:8] = bytes('\x00','latin1')*4 # CRC value is not part of data to calculate CRC
copy_img_str = ''.join([chr(x) for x in copy_img])
calc_hdr_crc = binascii.crc32(bytes(copy_img_str,'latin1'))

assert(calc_hdr_crc == header_crc)


print(f"Magic Number:{hex(magic_number)}")
print(f"Header CRC:{hex(header_crc)}")
print(f"Timestamp:{datetime.datetime.fromtimestamp(timestamp,datetime.timezone.utc)}")
print(f"Image Length:{image_len} bytes")
print(f"Loading from address {hex(load_addr)}")
print(f"Entry address {hex(entry_addr)}")
print(f"Image data CRC:{hex(data_crc)}")
print(f"Architecture:{arch[architecture]['id']}")
print(f"Os type:{os[os_type]['id']}")
print(f"Compression Type:{compression[compression_type]['id']}")
print(f"Image type:{image[image_type]['id']}")
print(f"Name:{image_name.decode('latin1')}")