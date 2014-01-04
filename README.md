scrypt
======

scrypt is a command line tool for encryption. It uses the Blake2b (https://blake2.net/) hash function to hash the provided encryption/decryption key and the salsa20, stream cipher implementation, by eSTREAM (ECRYPT Stream Cipher Project - http://www.ecrypt.eu.org/stream/e2-salsa20.html).

usage: scrypt { --help | -h | { -e | -d } } < input_file > output_file

--help | -h:        help
-e:                 encrypt
-d:                 decrypt
