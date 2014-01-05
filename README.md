<strong><h1>scrypt</h1></strong>
scrypt is a command line tool for encryption. It uses the Blake2b (https://blake2.net/) hash function to hash the provided encryption/decryption key and the salsa20, stream cipher implementation, by eSTREAM (ECRYPT Stream Cipher Project - http://www.ecrypt.eu.org/stream/e2-salsa20.html).<br /><br />
<strong>usage: scrypt { --help | -h | { -e | -d } } < input_file > output_file</strong><br /><br />
<strong>--help&nbsp;|&nbsp;-h</strong>:&nbsp;help<br />
<strong>-e</strong>:&nbsp;encrypt<br />
<strong>-d</strong>:&nbsp;decrypt<br /><br />
<strong>How to build:</strong>&nbsp;"make" creates "scrypt" (or "scrypt.exe" in cygwin) in the project's root directory.<br /><br />
<strong>Why it was built:</strong>&nbsp;tar cj ... | scrypt -e | ncat ... <-- internet --> ncat ... | scrypt -d | tar xj (i.e., easy usage in a pipeline).
