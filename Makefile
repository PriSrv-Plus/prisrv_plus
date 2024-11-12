export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	make -C MIRACL
	${CXX} -o  test_ctr test_hash_ctr.cpp hash_ctr.cpp bn_pair.cpp bn_transfer.cpp miracl.a -O2 -w
	${CXX} -o  test_feme test_feme.cpp feme.cpp bn_pair.cpp miracl.a -O2 -w
	${CXX} -o  test_prisrv_plus test_prisrv_plus.cpp prisrv_plus.cpp feme.cpp macddh.cpp hash_ctr.cpp bn_transfer.cpp bn_pair.cpp miracl.a -O2 -w
	${CXX} -fPIC -shared -o libprisrv_plus_export.so prisrv_plus_export.cpp prisrv_plus.cpp feme.cpp  hash_ctr.cpp bn_transfer.cpp bn_pair.cpp macddh.cpp miracl.a -fpermissive -Wwrite-strings -w -O2
	${CC} -o test_export test_prisrv_plus_export.cpp libprisrv_plus_export.so -w -O2
clean:
	rm -f *.a *.so 
	rm -f test_ctr
	rm -f test_feme
	rm -f test_prisrv_plus
	rm -f test_export
test:
	./test_ctr
	./test_feme
	./test_prisrv_plus
	./test_export


