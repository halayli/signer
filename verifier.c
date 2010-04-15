#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "signer_common.h"
#include "verifier.h"

extern int errno;

#define SECSIZE sizeof(Elf32_Shdr)
#define SECNSZ (strlen(secname))	/* section name length */

static char *extract_subject(char *cert);
static int is_certexpired(char *cert);

int
verify_binary(char *file, char *cacert) {

	int fd;			/* fd for unsigned exec & newly signed exec */
	Elf32_Ehdr ehead;		/* elf head */
	Elf32_Shdr *shead = NULL;	/* section head array */
	char *string_table = NULL ;	/* String table  */
	char *cert = NULL;
	char *subject = NULL;
	int secindex, err = 0;
	void *textseg = NULL;		/* For hashing the .text segment */
	unsigned char hash[EVP_MAX_MD_SIZE] = {0}; /* Hold the hash string */


	if ((fd = open(file, O_RDONLY)) == -1) {
		err = -1;
		goto err;
	}

	/* Read elf32 header */
	if (read(fd, &ehead, sizeof (Elf32_Ehdr)) != sizeof (Elf32_Ehdr)) {
		error();
		err = -1;
		goto err;
	}

	if (!is_elf(&ehead)) {
		return (-1);
	}

	/* *PSST* We also allocate additonal section when retrieving them*/
	if (get_section_entries(fd, &shead, ehead)) {
		error();
		err = -1;
		goto err;
	}

	/* Get string table section data */
	if (get_section_data(fd, shead[ehead.e_shstrndx].sh_offset,
	    (void **)&string_table, shead[ehead.e_shstrndx].sh_size)) {
		error();
		err = -1;
		goto err;
	}

	secindex = get_section_index(".text", shead, &ehead, string_table);
	if (secindex == -1) {
		err = -1;
		goto err;
	}
	if ((textseg = get_section_entry(fd, &shead[secindex])) == NULL) {
		error();
		err = -1;
		goto err;
	}
	gen_hash(textseg, shead[secindex].sh_size, hash);

	secindex = get_section_index("cert", shead, &ehead, string_table);
	if (secindex == -1) {
		err = CERT_NOT_FOUND;
		goto err;
	}

	if ((cert = get_section_entry(fd, &shead[secindex])) == NULL) {
		err = -1;
		goto err;
	}

	if (is_certexpired(cert)) {
		err = CERT_EXPIRED;
		goto err;
	}

	if ((subject = extract_subject(cert)) == NULL) {
		err = CERT_INVALID;
		goto err;
	}

	if(strcmp(hash, subject)) {
		err = CERT_NOT_MATCH;
		goto err;
	}


err:	if (shead)
		free(shead);
	if (textseg)
		free(textseg);
	if (cert)
		free(cert);
	if (subject)
		free(subject);
	close(fd);	

	return (err);

}

static char
*extract_subject(char *cert)
{
	X509 *x = NULL;
	char *sp, *subject;
	int size, outlen;
	BIO *bmem = BIO_new(BIO_s_mem());
	BIO *membuf = BIO_new(BIO_s_mem());

	BIO_puts(bmem, cert);
	if (!PEM_read_bio_X509(bmem, &x, 0, NULL)) {
		fprintf(stderr, "Incorrect certificate\n");
		return (NULL);
	}
	ASN1_STRING_print(membuf, X509_NAME_ENTRY_get_data(
	    X509_NAME_get_entry(X509_get_subject_name(x), 0)));
	BIO_write(membuf, &outlen, 1);
	size = BIO_get_mem_data(membuf, &sp);
	sp[size - 1] = '\0';

	if ((subject = malloc(size)) == NULL) {
		BIO_free_all(bmem);
		BIO_free_all(membuf);
		X509_free(x);
		return (NULL);
	}

	strcpy(subject, sp);

	BIO_free_all(bmem);
	BIO_free_all(membuf);
	X509_free(x);

	return (subject);
}

static int
is_certexpired(char *cert)
{
	X509 *x = NULL;
	BIO *bmem = BIO_new(BIO_s_mem());
	BIO_puts(bmem, cert);
	if (!PEM_read_bio_X509(bmem, &x, 0, NULL)) {
		fprintf(stderr, "Incorrect certificate\n");
		return (1);
	}

	BIO_free_all(bmem);

	if (X509_cmp_current_time(X509_get_notAfter(x)) < 0) {
		X509_free(x);
		return (1);
	}

	X509_free(x);

	return (0);
}
