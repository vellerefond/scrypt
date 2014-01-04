all: i386 amd64

folders:
	mkdir -p ./dist/i386 ./dist/amd64;

i386: folders
	gcc -std=c11 -Wall -Wno-int-to-pointer-cast -Wno-unused-variable -Wno-unused-function -Wno-implicit-function-declaration -Wno-comment -pedantic -m32 \
		./blake2b-ref.c ./ecrypt.c ./scrypt.c -o ./dist/i386/scrypt;

amd64: folders
	gcc -std=c11 -Wall -Wno-int-to-pointer-cast -Wno-unused-variable -Wno-unused-function -Wno-implicit-function-declaration -Wno-comment -pedantic -m64 \
		./blake2b-ref.c ./ecrypt.c ./scrypt.c -o ./dist/amd64/scrypt;

clean:
	rm -rf ./dist;
