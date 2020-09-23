all: h7shim

h7shim: HEAVEN7W_C.EXE h7shim.c
	gcc h7shim.c -o h7shim -Wall -Wextra -m32 -pthread

HEAVEN7W_C.EXE: HEAVEN7W.EXE
	cp HEAVEN7W.EXE HEAVEN7W_tmp.EXE
	upx -d HEAVEN7W_tmp.EXE
	mv HEAVEN7W_tmp.EXE HEAVEN7W_C.EXE
