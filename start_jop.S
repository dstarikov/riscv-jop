/* start_jop(void* stackbuf) */
.global start_jop
start_jop:
	mv sp, a0
	ld ra, 72(sp)
	addi sp, sp, 80
	ret
