/* start_jop(void* stackbuf) */
.global start_jop
start_jop:
	mv sp, a0
	ld a6, 8(sp)
	add sp, sp, 0x10
	c.jalr	a6
