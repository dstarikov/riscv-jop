.global nop_gadget
nop_gadget:
  c.ldsp a6, 8(sp)
  c.addi sp, 0x10
  c.jalr a6

.global pop_gadget
pop_gadget:
  c.ldsp a6, 0x28(sp)
  c.ldsp s0, 0x20(sp)
  c.ldsp a0, (sp)
  c.ldsp a1, 8(sp)
  c.ldsp s1, 0x18(sp)
  c.ldsp s2, 0x10(sp)
  c.addi16sp sp, 0x30
  c.jalr a6

.global read_mem_gadget
read_mem_gadget:
  c.ld a0, 8(a0)
  c.add a0, a5
  c.ldsp a4, 0x28(sp)
  c.ld a5, 0(s0)
  bne a4, a5, 0x1e
  c.ldsp a6, 0x38(sp)
  c.ldsp s0, 0x30(sp)
  c.addi16sp sp, 0x40
  c.jalr a6

.global pop_a0
pop_a0:
  ld  a0,8(sp)
  ld  a6,24(sp)
  addi  sp,sp,32
  c.jalr  a6

.global pop_s0
pop_s0:
  ld  a6,8(sp)
  ld  s0,0(sp)
  addi  sp,sp,16
  c.jalr a6

.global add_1a0
add_1a0:
  ld  a6,8(sp)
  ld  s0,0(sp)
  addi  a0,a0,1
  addi  sp,sp,16
  c.jalr a6

.global dec_2a0
dec_2a0:
  addi  a0,a0,-2
  ld  a6,8(sp)
  addi  sp,sp,16
  c.jalr a6

.global ld_a5_s0
ld_a5_s0:
  c.ldsp     a4,0x48(sp)
  c.ld       a5,0x0(s0)
  bne        a4,a5,0x10
  c.ldsp     a6,0x58(sp)
  c.ldsp     s0,0x50(sp)
  c.addi16sp sp,0x60
  c.jalr a6

.global ld_a0_8_a0
ld_a0_8_a0:
  ld  a0,8(a0)
  add a0,a0,a5
  ld  a4,40(sp)
  ld  a5,0(s0)
  // d3230 - TODO
  bne a4,a5,0x1e
  ld  a6,56(sp)
  ld  s0,48(sp)
  addi  sp,sp,64
  c.jalr a6

.global sd_a0_16_s0
sd_a0_16_s0:
  ld  a6,8(sp)
  sd  a0,16(s0)
  ld  s0,0(sp)
  addi  sp,sp,16
  c.jalr a6

.global pop_a5
pop_a5:
  ld  a5,8(sp)
  ld  a6,24(sp)
  mv  a0,a5
  addi  sp,sp,32
  c.jalr a6

.global call_a5
call_a5:
  jalr  a5
  ld  a6,8(sp)  
  sd  zero,80(s0)
  ld  s0,0(sp)
  addi  sp,sp,16
  c.jalr a6

.global longjmp
longjmp:
  ld  a6,0(a0)
  ld  s0,8(a0)
  ld  s1,16(a0)
  ld  s2,24(a0)
  ld  s3,32(a0)
  ld  s4,40(a0)
  ld  s5,48(a0)
  ld  s6,56(a0)
  ld  s7,64(a0)
  ld  s8,72(a0)
  ld  s9,80(a0)
  ld  s10,88(a0)
  ld  s11,96(a0)
  ld  sp,104(a0)
  fld fs0,112(a0)
  fld fs1,120(a0)
  fld fs2,128(a0)
  fld fs3,136(a0)
  fld fs4,144(a0)
  fld fs5,152(a0)
  fld fs6,160(a0)
  fld fs7,168(a0)
  fld fs8,176(a0)
  fld fs9,184(a0)
  fld fs10,192(a0)
  fld fs11,200(a0)
  seqz  a0,a1
  add a0,a0,a1
  c.jalr a6

.global seqz_a0
seqz_a0:
  seqz  a0,a0
  ld    a6,8(sp)
  addi  sp,sp,16
  c.jalr a6

.global pop_s0_s1_s2
pop_s0_s1_s2:
  ld  a6,24(sp)
  ld  s0,16(sp)
  ld  s1,8(sp)
  ld  s2,0(sp)
  addi  sp,sp,32
  c.jalr a6

.global add_a5_a0
add_a5_a0:
  add a5,a5,a0
  sd  a5,144(s2)
  ld  a6,40(sp)
  ld  s0,32(sp)
  ld  s1,24(sp)
  ld  s2,16(sp)
  ld  s3,8(sp)
  addi  sp,sp,48
  c.jalr a6

.global add_a0_a5
add_a0_a5:
  add a0,a0,a5
  beqz  a0,0xa
  ld  a6,72(sp)
  addi  sp,sp,80
  c.jalr a6
