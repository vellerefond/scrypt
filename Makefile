error:
	$(error No target specified. Target must be one of gcc or clang);

gcc clang:
	$@ -std=c11 -Wall -Wno-int-to-pointer-cast -Wno-unused-variable -Wno-unused-function -Wno-implicit-function-declaration -Wno-comment -pedantic \
		./blake2b-ref.c ./ecrypt.c ./scrypt.c -o ./scrypt;

clean:
	rm -rf ./scrypt ./scrypt.exe;
