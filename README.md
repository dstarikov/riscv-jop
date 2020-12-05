## Branch Descriptions
### master
brainfuck-to-ROP compiler modified to use handwritten gadgets extracted from the version of libc of the brainfuck-to-ROP paper.

### simple_jop
brainfuck-to-ROP compiler using handwritten gadgets that replace returns and jumps to `ra` with indirect jumps to `a6`

### jop-ret-gadget
brainfuck-to-ROP compiler for return-oriented-programming without returns. Uses handwritten JOP gadgets chained to a ret gadget

### jop_trampoline_shell
Implementation of a basic JOP chain to call `execve(/bin/sh)` using a few JOP gadgets

### jop
Implementation of JOP chains using the dispatchilizer gadget chains. Can print out arbitrary strings before opening a shell

### jop_longjmp
Implementation of JOP chains using the dispatchilizer gadget. Exploits a realistic buffer overflow vulnerability in a call to `longjmp`. Can print out arbitrary strings through JOP and pass in arbitrary strings to `execve`, allowing for execution
of any executables in addition to bash scripts. Contains an example of opening a reverse shell through this vulnerability. 

Requires prerequisite knowledge of which virtual addresses the dispatch buffers will be stored in to build the dispatch table.

### jop_longjmp_noaddress
Implementation of JOP chains using the dispatchilizer gadget. Exploits a realistic buffer overflow vulnerability in a call to
`longjmp`. Does not require the virtual addresses of the dispatch buffers as it uses a misinterpreted compressed instruction
to move the dispatch table pointer forward. This misinterpreted gadget limits the attack and only allows for a single function call which is used to run `execve(/bin/sh)`

### capstone-disas
Contains implementation of Galileo algorithm to find gadgets using misininterpreted compressed instructions.

