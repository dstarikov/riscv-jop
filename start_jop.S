/* start_jop(void* stackbuf) */
.global start_jop
start_jop:
	mv t0, a0
	ld t1, 0(t0)
	jalr t1
