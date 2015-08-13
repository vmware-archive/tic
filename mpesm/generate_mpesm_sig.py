#
# generate mpesm (Mnemonic PE Signature Matching) signature
# Copyright Bit9, Inc. 2015
#

import pefile
import sys
from capstone import *
from argparse import ArgumentParser

def main():
    parser = ArgumentParser(description="Mnemonic PE Signature Matching, signature generator")
    parser.add_argument("-n", "--num-mnem",
                        dest="num_mnem", help="Use a length of 'n' mnemonics (default: None)")
    parser.add_argument("-t", "--title",
                        dest="sig_title", help="Title (name) to use for the signature")
    parser.add_argument("-l", "--linker",
                        dest="linker", help="Use Major and Minor linker versions in the signature", action="store_true")
    parser.add_argument("-s", "--numofsections",
                        dest="nos", help="Use the number of sections in the PE file in the signature", action="store_true")
    parser.add_argument("file", nargs=1, help='File to analyze')
    args = parser.parse_args()

    try:
        pe = pefile.PE(args.file[0])
    except Exception as e:
        sys.stderr.write("[*] Error with %s - %s\n" %(sys.argv[1], str(e)))
        sys.exit(1)

    try:
        if args.sig_title and len(args.sig_title) > 0:
            print "[%s]" %(args.sig_title)

        if args.linker:
            maj_linker = 0
            min_linker = 0
            try:
                maj_linker = pe.OPTIONAL_HEADER.MajorLinkerVersion
                min_linker = pe.OPTIONAL_HEADER.MinorLinkerVersion
            except Exception as e:
                pass
            print "major_linker = %s" %(maj_linker)
            print "minor_linker = %s" %(min_linker)

        if args.nos:
            try:
                print "numberofsections = %s" %(pe.FILE_HEADER.NumberOfSections)
            except Exception as e:
                sys.stderr.write("Image File Header not found in PE file\n")

        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
        data = pe.get_memory_mapped_image()[ep:ep+500]
        #
        # Determine if the file is 32bit or 64bit
        #
        mode = CS_MODE_32
        if pe.OPTIONAL_HEADER.Magic == 0x20b:
            mode = CS_MODE_64

        md = Cs(CS_ARCH_X86, mode)
        match = []
        for (address, size, mnemonic, op_str) in md.disasm_lite(data, 0x1000):
            match.append(mnemonic.encode('utf-8').strip())

        print 'mnemonics = ' + ','.join(match[:30])
    except Exception as e:
        print str(e)

if __name__ == "__main__":
    main()
