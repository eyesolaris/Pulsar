.bitness 32 // Some commentary
.PROC ArraySum // Сумма массива
{
	// .I8 str "Hello\n\\~w45#*&#(&*&(# asj9338RUJf)*#uj)( \\ \t\v\bdf", 13, 0xA
	ALLOCVARS 4
	// r0 – адрес 64-битного массива, r1 – размер. Возврат значения в r3
	CPY.I64 local[0], offset ArraySum
	ADD.I64 R1,R0 // Получение адреса конца массива
	cycle:
	ADD.I64 LOCAL[0], R0
	INCR R0
	SUB.I64 R1, R0, ULESS cycle
helloLabel: CPY.I64 R3, LOCAL[0] // Установка возвращаемого значения
helloLabel1:
	RET
}

.proc outter
{
	cpy local[0], outter
	cpy local[0], cycle
}

cpy.a8 [0], 1

call ArraySum