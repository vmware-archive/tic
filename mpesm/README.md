# mpesm
## Mnemonic PE Signature Matching

mpesm uses a weighted distance metric to compare assembly mnemonics of a PE file to those in a signature in order to help determine the compiler/packer/cryptor that likely generated the file. 

More information is available under `docs/`


## Install

* Capstone Engine [http://www.capstone-engine.org/](http://www.capstone-engine.org/)
* `pip install -r requirements.txt`


## Usage 
### mpesm.py

In order to test the signatures against various files or a directory of files.

```
$ python ./mpesm.py -h
usage: mpesm.py [-h] [-n NUM_MNEM] [-s SIG_FILE] [-b BYTES] [-t THRESHOLD]
                [-v]
                file

Mnemonic PE Signature Matching

positional arguments:
  file                  File to analyze

optional arguments:
  -h, --help            show this help message and exit
  -n NUM_MNEM, --num-mnem NUM_MNEM
                        Use a lenght of 'n' mnemonics (default: 30)
  -s SIG_FILE, --signatures SIG_FILE
                        signature file to use (default: ./mpesm.sig)
  -b BYTES, --bytes BYTES
                        Grab and disassemble x bytes from EP, you should only
                        need to change this if you give a super large number
                        for -n (default: 500)
  -t THRESHOLD, --threshold THRESHOLD
                        Display all matches greater than -t supplied
                        similarity (default: 0.85)
  -v, --verbose         Verbose output
```

#### generate_mpesm_sig.py

```
$ python ./generate_mpesm_sig.py -h
usage: generate_mpesm_sig.py [-h] [-n NUM_MNEM] [-t SIG_TITLE] [-l] [-s] file

Mnemonic PE Signature Matching, signature generator

positional arguments:
  file                  File to analyze

optional arguments:
  -h, --help            show this help message and exit
  -n NUM_MNEM, --num-mnem NUM_MNEM
                        Use a length of 'n' mnemonics (default: None)
  -t SIG_TITLE, --title SIG_TITLE
                        Title (name) to use for the signature
  -l, --linker          Use Major and Minor linker versions in the signature
  -s, --numofsections   Use the number of sections in the PE file in the
                        signature
```
