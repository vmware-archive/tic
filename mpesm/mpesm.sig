[RAR SFX]
mnemonics = all,push,call,add,add,nop,push,mov,push,push,push,mov,mov,mov,mov,push,push,push,push,mov,mov,call,sub,je,dec,je,jmp,push,push,push,call,mov,jmp,and,dec,je,dec,je,jmp,push,push,push,push,call,push,push,call,mov,jmp,push,push,call,mov,jmp,xor,jmp,xor,pop,pop,pop,pop,ret,push,mov,push,mov,add,push,dec,jne,add,mov,push,push,push,mov,mov

[VISE Installer]
mnemonics = push,mov,push,push,push,mov,push,mov,sub,push,push,push,mov,call,xor,mov,mov,mov,and,mov,shl,add,mov,shr,mov,xor,push,call,pop,test

[Install Shield 2000]
mnemonics = push,mov,push,push,push,mov,push,mov,add,push,push,push,mov,mov,push,call,add,mov,mov,call,mov,mov,call,mov,mov,mov,mov,mov,call,mov

[MinGW GCC 3.x]
mnemonics = push,mov,sub,mov,call,call,nop,lea,push,mov,mov,pop,jmp,lea,push,mov,mov,pop,jmp,nop,nop,nop,nop,push,mov,mov,push,xor,lea,push,push,sub,mov,mov,mov,call,mov,mov,call,test,je,mov,xor,xor,mov,xor,mov,mov,call,sub,test,mov,je,lea,mov,mov,mov,mov,mov,call,sub
num_mnemonics = 20

[Microsoft Visual C++ 9 : Visual Studio 2008 SP1 : DLL : GUI]
mnemonics = cmp,jne,call,push,mov,mov,call,pop,ret,push,mov,sub,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,pushfd,pop,mov,mov,mov,mov

[Microsoft Visual C++ 9 : Visual Studio 2008 SP1 : GUI]
mnemonics = call,jmp,push,mov,sub,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,pushfd,pop,mov,mov,mov,mov,lea,mov,mov,mov,mov,mov,mov

[32bit .Net]
mnemonics = jmp,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add

[Microsoft Visual Basic v5.0/v6.0]
mnemonics = push,call,add,add,add,xor,add,dec,add,add,add,add,salc,adc,mov,retf,add,add,add,add,add,add,inc,adc,jae,insb,insb,jne,jae,imul,add,add,add,add,add,add,inc,add,add,add,inc,add,add,add,add,add,add,add,add

[Backoff Group 4]
mnemonics = push,mov,push,sub,call,call,call,mov,call,mov,mov,mov,mov,mov,mov,call,sub,mov,call,push,mov,mov,mov,mov,mov,mov,call,sub,mov,call,push,lea,mov,mov,mov,mov

[Backoff Group 2]
mnemonics = push,mov,sub,call,xor,leave,ret,nop,jmp,nop,nop

[UPX v0.89.6 - v1.02 / v1.05 -v1.24]
mnemonics = pushal,mov,lea,push,jmp,nop,mov,inc,mov,inc,add,jne,mov,sub,adc,jb,mov,add,jne,mov,sub,adc,adc,add,jae,jne,mov,sub,adc,jae

[UPX 2.93 - 3.00 : LZMA]
mnemonics = pushal,mov,lea,push,mov,lea,xor,push,cmp,jne,inc,inc,push,push,push,add,push,push,push,add,push,push,mov,nop,nop,nop,nop,nop,push,push

[UPX 2.90 : LZMA]
mnemonics = pushal,mov,lea,push,or,jmp,nop,nop,nop,nop,nop,nop,mov,inc,mov,inc,add,jne,mov,sub,adc,jb,mov,add,jne,mov,sub,adc,adc,add

[UPX v0.89.6 - v1.02 / v1.05 -v1.22 (Delphi) stub]
mnemonics = pushal,mov,lea,mov,push,or,jmp,nop,nop,nop,nop,mov,inc,mov,inc,add,jne,mov,sub,adc,jb,mov,add,jne,mov,sub,adc,adc,add,jae

[Microsoft Visual C : Visual Studio 2005 : Debug]
mnemonics = jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp,jmp

# lots of jdk6 and other java related stuff
# likely C++ but not 100%
[Microsoft Visual C++ : Visual Studio 2005]
mnemonics = push,push,call,xor,push,call,cmp,jne,mov,add,cmp,jne,movzx,cmp,je,cmp,je,mov,jmp,cmp,jbe,xor,cmp,jmp,cmp,jbe,xor,cmp,setne,mov

# possible service
[Micrsoft Visual C : Visual Studio 2005]
mnemonics = call,jmp,push,mov,sub,mov,mov,mov,shr,pxor,jmp,lea,nop,movdqa,movdqa,movdqa,movdqa,movdqa,movdqa,movdqa,movdqa,lea,dec,jne,mov,mov,pop,ret,push,mov

[Microsoft : Unknown : DLL]
mnemonics = dec,pop,add,add,add,add,add,add,add,add,add,add,add,inc,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add

[Microsoft : Visual Studio 2010 : DLL]
mnemonics = dec,pop,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add,add

[Microsoft : Visual Studio 2010]
mnemonics = dec,pop,nop,add,add,add,add

[CygWin : 64bit]
mnemonics = dec,sub,dec,lea,call,inc,xor,xor,xor,call,inc,xor,xor,xor,call,inc,xor,xor,xor,call,inc,xor,xor,xor,dec,add,jmp,nop,nop,nop

[CygWin : X11]
mnemonics = push,mov,sub,and,mov,call,mov,mov,mov,call,mov,mov,mov,call,mov,mov,mov,call,mov,mov,mov,call,leave,ret,nop,nop,nop,nop,nop,nop

[Visual C : Generic]
mnemonics = push,mov,push,push,push,mov,push,mov,sub,push,push,push,mov,call,xor,mov,mov,mov,and,mov,shl,add,mov,shr,mov,xor,push,call,pop,test

[InstallShield : v8, v9]
mnemonics = call,jmp,test,je,xor,test,setg,lea,mov,ret,movzx,movzx,sub,je,xor,test,setg,lea,mov,ret,mov,cmp,je,movzx,movzx,sub,je,xor,test,setg

[Microsoft Visual Studio : Real Mode Device Driver]
mnemonics = dec,mov,dec,mov,cdq,sub,add,sal,sal,lea,dec,mov,xor,dec,add,ror

# RootkitRevealer is picked up by this sig
[Microsoft : Visual Studio 2002/2003]
mnemonics = push,mov,push,push,push,mov,push,mov,sub,push,push,push,mov,call,xor,mov,mov,mov,and,mov,shl,add,mov,shr,mov,push,call,pop,test,jne

[Google Toolchain]
mnemonics = push,call,push,call,pop,push,call,int3,push,mov,mov,lea,cmp,ja,add,mov,lea,cmp,ja,add,xor,cmp,sete,mov,pop,ret,push,mov,push,mov

[Google Chrome Setup]
mnemonics = calljmp,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,cmp,jae,cmp,jae,shrd,shr,ret,mov,xor,and,shr,ret,xor,xor,ret,int3

[Microsoft Visual C++: Visual Studio 2012]
mnemonics = call,jmp,push,push,call,and,call,movzx,and,mov,mov,xor,mov,mov,xor,lock cmpxchg,test,je,cmp,jne,xor,inc,mov,jmp,xor,inc,cmp,jne,push,call

[Microsoft Visual C++ : Visual Studio 2013 Professional]
mnemonics = call,jmp,jmp,jmp,jmp,push,mov,mov,mov,cmp,jne,cmp,jne,mov,cmp,je,cmp,je,cmp,je,cmp,je,xor,pop,ret,call,int3,push,call,pop

[Microsoft Visual C++ : Visual Studio 2013 Professionali : DLL]
mnemonics = push,mov,cmp,jne,call,push,push,push,call,add,pop,ret,push,push,call,xor,inc,mov,mov,xor,mov,mov,mov,mov,test,jne,cmp,je,cmp,je

[Microsoft Visual C++ : Visual Studio 2013 Professional : Real Mode Device Driver]
mnemonics = mov,push,mov,call,pop,jmp,mov,push,mov,push,push,mov,mov,test,je,cmp,jne,rdtsc,xor,mov,mov,jne,mov,mov,not,mov,mov,pop,ret,inc

[PECompact 3.03 beta : pec2ldr_default.dll, pec2ldr_antidebug.dll, pec2ldr_no_rwx_mem.dll : pec2codec_lzma2.dll]
mnemonics = mov,push,push,mov,xor,mov,push,inc,inc,outsd,insd,jo,arpl,mov,test,and,xchg,add,out,adc,enter,push,loopne,stosb,xor,cmpsb,jp,jo,out,pop

[PECompact 3.03 beta : pec2ldr_reduced.dll : pec2codec_lzma2.dll]
mnemonics = mov,push,push,mov,xor,mov,push,inc,inc,xor

[Microsoft Visual C++ : Visual Studio 2008, 2010 : 64bit]
mnemonics = dec,sub,call,dec,add,jmp,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,nop,dec,cmp,jne,dec,rol,test,jne,ret,dec,ror,jmp

[[Microsoft Visual C++ : Visual Studio 2008, 2010, 2012 : 64bit]]
mnemonics = dec,sub,call,dec,add,jmp,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,int3,nop,dec,cmp,jne

# Possible service
[Microsoft : Visual Studio 2005, 2010]
mnemonics = call,jmp,mov,push,mov,sub,mov,push,push,push,pop,mov,lea,rep movsd,mov,mov,pop,mov,pop,test,je,test,je,mov,lea,push,push,push,push,call

[Microsoft : Visual Studio 2005, 2008, 2010 : DLL]
mnemonics = mov,push,mov,cmp,jne,call,push,mov,mov,call,pop,pop,ret,mov,push,mov,sub,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,mov,pushfd

[Microsoft : AntiMalware Definition Update]
mnemonics = mov,push,mov,and,sub,mov,xor,mov,push,xor,mov,push,push,mov,mov,mov,mov,mov,mov,mov,call,push,call,test,je,push,push,call,test,je

[Apple utild ls]
mnemonics = push,mov,push,push,push,push,push,sub,mov,mov,lea,mov,test,jg,call,lea,xor,call,mov,mov,call,test,je,mov,lea,call,test,je,cmp,je

[Apple utils zsh]
mnemonics = push,mov,pop,jmp,nop,nop,push,mov,lea,mov,xor,call,lea,mov,lea,mov,mov,mov,mov,mov,mov,mov,mov,mov,lea,mov,mov,lea,mov,mov

[Apple utils /bin/test]
mnemonics = push,mov,push,push,push,push,mov,mov,mov,test,je,lea,call,test,jne,dec,movsxd,mov,lea,call,test,jne,mov,dec,cmp,jbe,add,mov,mov,mov

[Apple utils /bin/bash]
mnemonics = push,mov,push,push,push,push,push,sub,mov,mov,mov,lea,mov,call,test,jne,lea,lea,call,mov,call,jmp,mov,call,cmp,jne,call,call,mov,cmp

