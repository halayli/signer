/* Returns 0 if binary is verified, -1 for system call error, or 1 for crypto error
   arg1: the executable path to be verified
   arg2: the root's public certificate.
   NOTE: the second argument is not used for now, and it is only there so that the interface doesn't get modified in the future */

enum {CERT_NOT_MATCH = 1, CERT_INVALID, CERT_EXPIRED, CERT_NOT_FOUND};
int verify_binary(char *, char *);
