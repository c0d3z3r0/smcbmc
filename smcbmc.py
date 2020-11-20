#!/usr/bin/env python3

import argparse
import math
import shutil
import os
import zlib
from mmap import mmap, PROT_READ
from Crypto.Cipher import AES

__author__      = "Michael Niewöhner"
__copyright__   = "Copyright 2020, Michael Niewöhner"
__license__     = "GPLv2"


REGIONS = {
    'meta':     { 'offset': 0x01fc0000, 'enc_hdr_len': 0xc0, },
    'rootfs':   { 'offset': 0x00400000, 'enc_hdr_len': 0x60, },
    'webfs':    { 'offset': 0x01700000, 'enc_hdr_len': 0x60, },
}

CRYPTO_STR = 'crypto_task{id}\x00\x00\x00\x00'

def decompress_multi(data):
    ret = b''

    while True:
        if not data:
            return ret

        z = zlib.decompressobj()
        ret += z.decompress(data)
        data = z.unused_data

def read_int(mm, size):
    return int.from_bytes(mm.read(size), 'little')

def extract_keys(mm):
    rootfs_off      = REGIONS['rootfs']['offset']
    inode_off       = mm.find(b"libipmi.so", rootfs_off, REGIONS['webfs']['offset'])

    mm.seek(inode_off - 8)
    file_size       = read_int(mm, 4) & 0xffffff
    offset_namelen  = read_int(mm, 4)
    chunk_ptr_off   = (offset_namelen & ~0x3f) >> 4
    chunk_count     = math.ceil(file_size / 4096)
    data_off        = chunk_ptr_off + chunk_count * 4
    last_ptr_off    = data_off - 4

    mm.seek(rootfs_off + last_ptr_off)
    data_end        = read_int(mm, 4)
    data_len        = data_end - data_off

    with mmap(-1, file_size) as mi:
        #mm.seek(data_off)  # we're here already
        mi.write(decompress_multi(mm.read(data_len)))
        mi.seek(0)

        ret = REGIONS

        ct1_off   = mi.find(CRYPTO_STR.format(id=1).encode())
        mi.seek(ct1_off - 4 * 16)
        ret['rootfs']['key'] = mi.read(16)
        ret['webfs']['key']  = mi.read(16)
        ret['rootfs']['iv']  = mi.read(16)
        ret['webfs']['iv']   = mi.read(16)

        ct2_off   = mi.find(CRYPTO_STR.format(id=2).encode())
        mi.seek(ct2_off - 2 * 16)
        ret['meta'].update({'key': mi.read(16), 'iv': mi.read(16)})

        return ret

def decrypt_header(mm, header):
    mm.seek(header['offset'])
    cipher = AES.new(header['key'], AES.MODE_CBC, iv=header['iv'])
    ret = cipher.decrypt(mm.read(header['enc_hdr_len']))

    return ret

def write_header(mm, header, data):
    if not len(data) == header['enc_hdr_len']:
        raise Exception(f"Wrong data length for headr at offset {header['offset']}")

    mm.seek(header['offset'])
    mm.write(data)

def decrypt_image(infile, outfile):
    shutil.copyfile(infile, outfile)
    with open(outfile, "r+b") as f,\
         mmap(f.fileno(), 0) as mm:
            regions = extract_keys(mm)
            for reg in regions.values():
                dec = decrypt_header(mm, reg)
                write_header(mm, reg, dec)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Decrypt Supermicro BMC firmware images.')
    parser.add_argument('infile', help='file to decrypt')
    parser.add_argument('outfile', help='output')
    args = parser.parse_args()

    decrypt_image(args.infile, args.outfile)
