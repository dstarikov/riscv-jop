/* start_jop(void* stackbuf) */
.global start_jop
start_jop:
	mv sp, a0
	ld a6, 0x68(sp)
	add sp, sp, 0x70
	c.jalr	a6
