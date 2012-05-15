#!/usr/bin/env python

# Copyright (C) 2012 Vincent Povirk
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

def get_big_endian_uint(string):
    result = 0
    for char in string:
        result = result << 8 | ord(char)
    return result

def read_checked(f, length):
    result = f.read(length)
    if len(result) < length:
        raise Exception("Unexpected end of file.")
    return result

def patch_ips(patch, basefile):
    magic = patch.read(5)
    if magic != 'PATCH':
        raise Exception("Not a valid IPS patch file.")

    while True:
        offset = read_checked(patch, 3)
        if offset == 'EOF':
            break

        offset = get_big_endian_uint(offset)

        size = get_big_endian_uint(read_checked(patch, 2))

        if size == 0:
            # RLE record
            count = get_big_endian_uint(read_checked(patch, 2))
            char = read_checked(patch, 1)

            if count == 0:
                print "WARNING: Got RLE record with count of 0"

            basefile.seek(offset)

            if count >= 4096:
                block = char * 4096

                while count >= 4096:
                    basefile.write(block)
                    count -= 4096

            if count:
                basefile.write(char * count)

        else:
            # Uncompressed data
            basefile.seek(offset)

            while size >= 4096:
                data = read_checked(patch, 4096)
                basefile.write(data)
                size -= 4096

            if size:
                data = read_checked(patch, size)
                basefile.write(data)

    if patch.read(1):
        print "WARNING: Don't know how to handle extra data after EOF!"

def main(argv):
    if len(argv) < 2:
        print 'Usage: %s basefile < patch.ips' % argv[0]
        return 1

    basefile = open(argv[1], 'r+b')

    try:
        patch_ips(sys.stdin, basefile)
    finally:
        basefile.close()

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))

