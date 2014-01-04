#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <termios.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include "blake2.h"
#include "blake2-impl.h"
#include "ecrypt-sync.h"

const int SECURE_SPACE_BLOCK_BYTE_COUNT = 4096,
	  SECURE_SPACE_BYTE_COUNT = 3 * 4096, /* 3 * SECURE_SPACE_BLOCK_BYTE_COUNT */
	  PASSWORD_LENGTH_MAX = 64,
	  IV_LENGTH_MAX = 8;
unsigned char *secure_bytes = (unsigned char *)NULL;
ECRYPT_ctx ecrypt_struct;
enum {
	ENCRYPT,
	DECRYPT
} operation;
const char *msg_usage = "usage: %s { --help | -h | { -e | -d } } < input_file > output_file",
	   *msg_nofile = "Could not open file",
	   *msg_init = "Failed to initialise.",
	   *msg_sig = "Received termination signal.",
	   *msg_password = "Could not read password.",
	   *msg_secure_password = "Could not read password securely.",
	   *msg_password_mismatch = "The passwords do not match.",
	   *msg_password_prompt = "Password: ",
	   *msg_password_confirm = "Confirm password: ",
	   *msg_in_unreadable = "Cannot read input.",
	   *msg_out_unwritable = "Cannot write output.";

volatile sig_atomic_t received_sig = 0;

static void show_msg(const char *msg, char *arg, int append_nl) {
	int has_arg = (arg != (char *)NULL);

	fprintf(stderr,
		"%s%s%s%c",
		msg,
		(has_arg ? ": " : ""),
		(has_arg ? arg : ""),
		(append_nl ? '\n' : '\0'));
}

static void alert(const char *msg) {
	show_msg(msg, (char *)NULL, 0);
}

static void alertn(const char *msg) {
	show_msg(msg, (char *)NULL, 1);
}

static void alerta(const char *msg, char *arg) {
	show_msg(msg, arg, 0);
}

static void alertan(const char *msg, char *arg) {
	show_msg(msg, arg, 0);
}

void reverse(char s[]) /* K&R implementation */
{
    int i, j;
    char c;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
	c = s[i];
	s[i] = s[j];
	s[j] = c;
    }
}

char *itoa(int n, char s[]) /* K&R implementation */
{
    int i, sign;

    if ((sign = n) < 0)  /* record sign */
	n = -n;          /* make n positive */
    i = 0;
    do {       /* generate digits in reverse order */
	s[i++] = n % 10 + '0';   /* get next digit */
    } while ((n /= 10) > 0);     /* delete it */
    if (sign < 0)
	s[i++] = '-';
    s[i] = '\0';
    reverse(s);

    return s;
}

void sig_handler(int sig) {
	received_sig = 1;
}

static void term(int status) {
	if (secure_bytes != (unsigned char *)NULL) {
		memset(secure_bytes, 0, SECURE_SPACE_BYTE_COUNT * sizeof(unsigned char));

#ifdef _POSIX_MEMLOCK_RANGE
		munlock(secure_bytes, SECURE_SPACE_BYTE_COUNT * sizeof(unsigned char));
#endif
	
		free(secure_bytes);
	}

	memset(&ecrypt_struct, 0, sizeof(ECRYPT_ctx));

#ifdef _POSIX_MEMLOCK_RANGE
	munlock(&ecrypt_struct, sizeof(ECRYPT_ctx));
#endif

	exit(status);
}

static void err_exit(const char *msg) {
	alertn(msg);
	term(EXIT_FAILURE);
}

static void init(void) {
	setbuf(stdout, NULL);

	sigset_t sigs_all;
	sigfillset(&sigs_all);
	if (sigprocmask(SIG_SETMASK, &sigs_all, (sigset_t *)NULL) == -1)
		err_exit(msg_init);

	secure_bytes = (unsigned char *)memalign(SECURE_SPACE_BLOCK_BYTE_COUNT, SECURE_SPACE_BYTE_COUNT * sizeof(unsigned char));

#ifdef _POSIX_MEMLOCK_RANGE
	if (mlock(secure_bytes, SECURE_SPACE_BYTE_COUNT * sizeof(unsigned char)) == -1 ||
	    mlock(&ecrypt_struct, sizeof(ECRYPT_ctx)) == -1)
		err_exit(msg_init);
#endif

	struct sigaction sa = {
		.sa_handler = sig_handler,
		.sa_mask = sigs_all,
		.sa_flags = SA_RESTART
	};

	if (sigaction(SIGINT, &sa, (struct sigaction *)NULL) == -1 ||
	    sigaction(SIGTERM, &sa, (struct sigaction *)NULL) == -1)
		err_exit(msg_init);
	
	sigset_t sigs_allowed;
	sigemptyset(&sigs_allowed);
	sigaddset(&sigs_allowed, SIGINT);
	sigaddset(&sigs_allowed, SIGTERM);
	sigaddset(&sigs_allowed, SIGSEGV);
	if (sigprocmask(SIG_UNBLOCK, &sigs_allowed, (sigset_t *)NULL) == -1)
		err_exit(msg_init);
	
	if (received_sig)
		err_exit(msg_sig);
}

static int must_terminate(void) {
	return received_sig;
}

static int read_password(void) {
	int pass_length = -1;

	int tty_fd = open("/dev/tty", O_RDWR);

	if (tty_fd == -1) {
		tty_fd = open("/proc/self/ctty", O_RDONLY);

		if (tty_fd == -1)
			err_exit(msg_password);

		char tty_path[PATH_MAX];

		int path_length = read(tty_fd, tty_path, PATH_MAX);

		close(tty_fd);

		if (path_length == -1)
			err_exit(msg_password);

		tty_path[path_length - 1] = '\0';

		tty_fd = open(tty_path, O_RDONLY);

		if (tty_fd == -1)
			err_exit(msg_password);
	}

	struct termios tios_orig, tios;
	
	if (tcgetattr(tty_fd, &tios_orig) == -1) {
		close(tty_fd);
		err_exit(msg_secure_password);
	}

	tios = tios_orig;

	tios.c_lflag &= ~ECHO;

	if (tcsetattr(tty_fd, TCSAFLUSH, &tios) == -1) {
		close(tty_fd);
		err_exit(msg_secure_password);
	}
	
	write(tty_fd, msg_password_prompt, strlen(msg_password_prompt));

	unsigned char *pass1 = &secure_bytes[2 * SECURE_SPACE_BLOCK_BYTE_COUNT],
		      *pass2 = &secure_bytes[(2 * SECURE_SPACE_BLOCK_BYTE_COUNT) + PASSWORD_LENGTH_MAX];

	int pass1_length;
	
	do {
		memset(pass1, 0, PASSWORD_LENGTH_MAX);
		pass1_length = read(tty_fd, pass1, PASSWORD_LENGTH_MAX);
	} while (pass1_length == -1 && errno == EINTR);

	if (pass1_length == -1) {
		tcsetattr(tty_fd, TCSAFLUSH, &tios_orig);
		close(tty_fd);
		err_exit(msg_secure_password);
	}

	pass1[pass1_length - 1] = '\0';
	
	write(tty_fd, "\n", 1);

	if (operation == DECRYPT) {
		memcpy(pass2, pass1, PASSWORD_LENGTH_MAX);
		memset(pass1, 0, PASSWORD_LENGTH_MAX);
		tcsetattr(tty_fd, TCSAFLUSH, &tios_orig);
		close(tty_fd);
		return pass1_length;
	}

	write(tty_fd, msg_password_confirm, strlen(msg_password_confirm));

	int pass2_length;

	do {
		memset(pass2, 0, PASSWORD_LENGTH_MAX);
		pass2_length = read(tty_fd, pass2, PASSWORD_LENGTH_MAX);
	} while (pass2_length == -1 && errno == EINTR);
	
	write(tty_fd, "\n", 1);

	if (pass2_length == -1) {
		tcsetattr(tty_fd, TCSAFLUSH, &tios_orig);
		close(tty_fd);
		err_exit(msg_secure_password);
	}

	pass2[pass2_length - 1] = '\0';

	if (pass1_length == pass2_length &&
	    strcmp((const char *)pass1, (const char *)pass2) == 0)
		pass_length = pass2_length - 1;
	else
		memset(pass2, 0, PASSWORD_LENGTH_MAX);
	
	memset(pass1, 0, PASSWORD_LENGTH_MAX);
	
	if (tcsetattr(tty_fd, TCSAFLUSH, &tios_orig) == -1) {
		close(tty_fd);
		err_exit(msg_secure_password);
	}

	close(tty_fd);

	return pass_length;
}

static int scrypt(void) {
	int in_fd_flags;
	unsigned char * const plaintext = secure_bytes,
		      * const ciphertext = secure_bytes + SECURE_SPACE_BLOCK_BYTE_COUNT,
		      * const key = secure_bytes + (2 * SECURE_SPACE_BLOCK_BYTE_COUNT),
		      * const iv = secure_bytes + (2 * SECURE_SPACE_BLOCK_BYTE_COUNT) + (PASSWORD_LENGTH_MAX / 2);
	
	if (fcntl(STDIN_FILENO, F_GETFL, &in_fd_flags) == -1)
		err_exit(msg_in_unreadable);
	
	in_fd_flags &= O_NONBLOCK;

	if (fcntl(STDIN_FILENO, F_SETFL, &in_fd_flags) == -1)
		err_exit(msg_in_unreadable);
	
	blake2b(key,
		key + PASSWORD_LENGTH_MAX,
		key + PASSWORD_LENGTH_MAX,
		PASSWORD_LENGTH_MAX,
		strlen((const char *)(key + PASSWORD_LENGTH_MAX)),
		strlen((const char *)(key + PASSWORD_LENGTH_MAX)));

	memset(key + PASSWORD_LENGTH_MAX, 0, PASSWORD_LENGTH_MAX);

	memset(secure_bytes, 0, 2 * SECURE_SPACE_BLOCK_BYTE_COUNT);

	int bytes_read;

	for (;;) {		
		if (must_terminate())
			err_exit(msg_sig);

		bytes_read = read(STDIN_FILENO, plaintext, SECURE_SPACE_BLOCK_BYTE_COUNT);

		if (must_terminate())
			err_exit(msg_sig);

		if (bytes_read == -1)
			err_exit(msg_in_unreadable);

		if (bytes_read == 0)
			break;

		ECRYPT_keysetup(&ecrypt_struct,
				key,
				(PASSWORD_LENGTH_MAX / 2) * 8,
				IV_LENGTH_MAX * 8);

		ECRYPT_ivsetup(&ecrypt_struct, iv);

		(operation == ENCRYPT ?
			ECRYPT_encrypt_bytes :
			ECRYPT_decrypt_bytes)(&ecrypt_struct,
					      plaintext,
					      ciphertext,
					      bytes_read);

		memset(plaintext, 0, SECURE_SPACE_BLOCK_BYTE_COUNT);

		if (write(STDOUT_FILENO, ciphertext, bytes_read) != bytes_read)
			err_exit(msg_out_unwritable);

		memset(ciphertext, 0, SECURE_SPACE_BLOCK_BYTE_COUNT);

		if (must_terminate())
			err_exit(msg_sig);

		if (bytes_read < SECURE_SPACE_BLOCK_BYTE_COUNT)
			break;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
	char msg_usage_formatted[1024];

	snprintf(msg_usage_formatted, 1024, msg_usage, argv[0]);

	if (argc != 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
		err_exit(msg_usage_formatted);
	
	int opt;

	while ((opt = getopt(argc, argv, "edl:")) != -1)
		switch (opt) {
		case 'e':
			operation = ENCRYPT;
			break;
		case 'd':
			operation = DECRYPT;
			break;
		default:
			err_exit(msg_usage_formatted);
		}	
	init();

	int pass_length = read_password();

	if (pass_length == -1)
		err_exit(msg_password_mismatch);
	
	term(scrypt());

	return EXIT_FAILURE;
}
