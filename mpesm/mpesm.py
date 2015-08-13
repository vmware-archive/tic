#
# mpesm (Mnemonic PE Signature Matching)
# Copyright Bit9, Inc. 2015
#

import os
import sys
import glob
import pefile
import ConfigParser
from capstone import *
from argparse import ArgumentParser

def tapered_levenshtein(s1, s2):
    max_len = float(max(len(s1), len(s2)))
    if len(s1) < len(s2):
        return tapered_levenshtein(s2, s1)

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            taper = 1.0 - min(i, j) / max_len
            insertions = previous_row[j + 1] + taper # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + taper       # than s2
            substitutions = previous_row[j] + (c1 != c2) * taper
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def main():
    BYTES = 500
    NUM_MNEM = 30
    SIG_FILE = "./mpesm.sig"
    THRESHOLD = .85
    VERBOSE = False
    DIR_PROCESSING = False
    signatures = {}
    file_list = []

    parser = ArgumentParser(description="Mnemonic PE Signature Matching")
    parser.add_argument("-n", "--num-mnem",
                        dest="num_mnem", help="Use a lenght of 'n' mnemonics (default: " + str(NUM_MNEM) + ')') 
    parser.add_argument("-s", "--signatures",
                        dest="sig_file", help="signature file to use (default: " + SIG_FILE + ')')
    parser.add_argument("-b", "--bytes",
                        dest="bytes", help="Grab and disassemble x bytes from EP, you should only need to change this if you give a super large number for -n (default: " + str(BYTES) + ')')
    parser.add_argument("-t", "--threshold",
                        dest="threshold", help="Display all matches greater than -t supplied similarity (default: " + str(THRESHOLD) + ')')
    parser.add_argument("-v", "--verbose",
                        dest="verbose", help="Verbose output", action='store_true')
    parser.add_argument("file", nargs=1, help='File to analyze')
    args = parser.parse_args()

    if args.sig_file:
        SIG_FILE = args.sig_file
    if args.threshold:
        THRESHOLD = float(args.threshold)
    if args.bytes:
        BYTES = args.bytes
    if args.num_mnem:
        NUM_MNEM = args.num_mnem
    if args.verbose:
        VERBOSE = True
   
    config = ConfigParser.RawConfigParser()
    config.read(SIG_FILE)

    if len(config.sections()) == 0:
        print "Error Reading from config file: %s, it's either empty or not present" %(SIG_FILE)
        sys.exit(1)    
    for s in config.sections():
        signatures[s] = {}
        signatures[s]['mnemonics'] = config.get(s, 'mnemonics').split(',')
        if config.has_option(s, 'num_mnemonics'):
            signatures[s]['num_mnemonics'] = config.getint(s, 'num_mnemonics')
        if config.has_option(s, 'major_linker'):
            signatures[s]['major_linker'] = config.getint(s, 'major_linker')
        if config.has_option(s, 'minor_linker'):
            signatures[s]['minor_linker'] = config.getint(s, 'minor_linker')
        if config.has_option(s, 'numberofsections'):
            signatures[s]['numberofsections'] = config.getint(s, 'numberofsections')

    if os.path.isdir(args.file[0]):
        file_list = glob.glob(args.file[0]+'/*')
        DIR_PROCESSING = True
    else:
        file_list.append(args.file[0])
   
    for f in file_list: 
        if VERBOSE:
            print '[*] Processing: ' + f
        try:
            pe = pefile.PE(f)
        except Exception as e:
            if VERBOSE or DIR_PROCESSING:
                sys.stderr.write("[*] Error with %s - %s\n" %(f, str(e)))
            continue
        
        try:
            minor_linker = 0
            major_linker = 0
            try:
                minor_linker = pe.OPTIONAL_HEADER.MinorLinkerVersion
                major_linker = pe.OPTIONAL_HEADER.MajorLinkerVersion
            except Exception as e:
                pass
            nos = pe.FILE_HEADER.NumberOfSections
            
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
            data = pe.get_memory_mapped_image()[ep:ep+BYTES]
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
        
            lsh = lsh_sims.LSHSimilarities([])
        
            for s in signatures:
                m = match
                sig = signatures[s]['mnemonics']
                additional_info = []
                if 'minor_linker' in signatures[s]:
                    if minor_linker == signatures[s]['minor_linker']:
                        additional_info.append('Minor Linker Version Match: True')
                    else:
                        additional_info.append('Minor Linker Version Match: False')
                if 'major_linker' in signatures[s]:
                    if major_linker == signatures[s]['major_linker']:
                        additional_info.append('Major Linker Version Match: True')
                    else:
                        additional_info.append('Major Linker Version Match: False')
                if 'numberofsections' in signatures[s]:
                    if nos == signatures[s]['numberofsections']:
                        additional_info.append('Number Of Sections Match: True')
                    else:
                        additional_info.append('Number Of Sections Match: False')
                
                if 'num_mnemonics' in signatures[s]:
                    nm = signatures[s]['num_mnemonics']
                    m = match[:nm]
                    sig = signatures[s]['mnemonics'][:nm]
                else:
                    m = match[:NUM_MNEM]
                    sig = signatures[s]['mnemonics'][:NUM_MNEM]
                distance = tapered_levenshtein(sig, m)
                similarity = 1.0 - distance/float(max(len(sig), len(m)))
                if similarity > THRESHOLD:
                    if DIR_PROCESSING:
                        print "[%s] [%s] (Edits: %s | Similarity: %0.3f) (%s)" %(f, s, distance, similarity, ' | '.join(additional_info))
                    else:
                        print "[%s] (Edits: %s | Similarity: %0.3f) (%s)" %(s, distance, similarity, ' | '.join(additional_info))
                    if VERBOSE:
                        print "%s\n%s\n" %(sig, m)
        except Exception as e:
            print str(e)

if __name__ == "__main__":
    main()
