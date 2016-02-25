#
# generate mpesm (Mnemonic PE Signature Matching) signature
# Copyright Bit9, Inc. 2015
#

import macholib.MachO
import pefile
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
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


    file_type = None
    filename = args.file[0]
    error = ''
    try:
        fe = pefile.PE(filename)
        file_type = 'PE'
    except Exception as e:
        error = str(e)
        pass

    if not file_type:
        try:
            fe = macholib.MachO.MachO(filename)
            file_type = 'MACHO'

        except Exception:
            error = str(e)
            pass

    if not file_type:
        sys.stderr.write("[*] Error with %s - not a PE or Mach-O\n" % sys.argv[1])
        sys.exit(1)

    if file_type == 'PE':
        try:
            if args.sig_title and len(args.sig_title) > 0:
                print "[%s]" %(args.sig_title)

            if args.linker:
                maj_linker = 0
                min_linker = 0
                try:
                    maj_linker = fe.OPTIONAL_HEADER.MajorLinkerVersion
                    min_linker = fe.OPTIONAL_HEADER.MinorLinkerVersion
                except Exception as e:
                    pass
                print "major_linker = %s" %(maj_linker)
                print "minor_linker = %s" %(min_linker)

            if args.nos:
                try:
                    print "numberofsections = %s" %(fe.FILE_HEADER.NumberOfSections)
                except Exception as e:
                    sys.stderr.write("Image File Header not found in PE file\n")

            ep = fe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_ava = ep+fe.OPTIONAL_HEADER.ImageBase
            data = fe.get_memory_mapped_image()[ep:ep+500]
            #
            # Determine if the file is 32bit or 64bit
            #
            mode = CS_MODE_32
            if fe.OPTIONAL_HEADER.Magic == 0x20b:
                mode = CS_MODE_64

            md = Cs(CS_ARCH_X86, mode)
            match = []
            for (address, size, mnemonic, op_str) in md.disasm_lite(data, 0x1000):
                match.append(mnemonic.encode('utf-8').strip())

            print 'mnemonics = ' + ','.join(match[:30])
        except Exception as e:
            print str(e)

    elif file_type == 'MACHO':
        f = open(filename, 'rb')
        macho_data = f.read()
        f.close()
        for header in fe.headers:
            # Limit it to X86
            if header.header.cputype not in [7, 0x01000007]:
                continue

            # Limit it to Object and Executable files
            if header.header.filetype not in [1, 2]:
                continue

            magic = int(header.MH_MAGIC)
            offset = int(header.offset)

            all_sections = []
            entrypoint_type = ''
            entrypoint_address = 0
            for cmd in header.commands:
                load_cmd = cmd[0]
                cmd_info = cmd[1]
                cmd_data = cmd[2]
                cmd_name = load_cmd.get_cmd_name()
                if cmd_name in ('LC_SEGMENT', 'LC_SEGMENT_64'):
                    for section_data in cmd_data:
                        sd = section_data.describe()
                        all_sections.append(sd)

                elif cmd_name in ('LC_THREAD', 'LC_UNIXTHREAD'):
                    entrypoint_type = 'old'
                    flavor = int(struct.unpack(header.endian + 'I', cmd_data[0:4])[0])
                    count = int(struct.unpack(header.endian + 'I', cmd_data[4:8])[0])
                    if flavor == 1:
                        entrypoint_address = int(struct.unpack(header.endian + 'I', cmd_data[48:52])[0])
                    elif flavor == 4:
                        entrypoint_address = int(struct.unpack(header.endian + 'Q', cmd_data[136:144])[0])

                elif cmd_name == 'LC_MAIN':
                    entrypoint_type = 'new'
                    entrypoint_address = cmd_info.describe()['entryoff']

            entrypoint_data = ''
            if entrypoint_type == 'new':
                entrypoint_offset = offset + entrypoint_address
                entrypoint_data = macho_data[entrypoint_offset:entrypoint_offset+500]
            elif entrypoint_type == 'old':
                found_section = False
                for sec in all_sections:
                    if entrypoint_address >= sec['addr'] and entrypoint_address < (sec['addr'] + sec['size']):
                        found_section = True
                        entrypoint_address = (entrypoint_address - sec['addr']) + sec['offset']
                        break

                if found_section:
                    entrypoint_offset = offset + entrypoint_address
                    entrypoint_data = macho_data[entrypoint_offset:entrypoint_offset+500]

            mode = CS_MODE_32
            if magic == 0xcffaedfe:
                mode = CS_MODE_64

            md = Cs(CS_ARCH_X86, mode)
            match = []  
            try:
                for (address, size, mnemonic, op_str) in md.disasm_lite(entrypoint_data, 0x1000):
                    match.append(mnemonic.encode('utf-8').strip())
            except Exception as e:
                print str(e)
            print 'mnemonics = ' + ','.join(match[:30])

if __name__ == "__main__":
    main()
