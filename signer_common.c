#include <string.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "signer_common.h"

extern int errno;

#define SECSIZE sizeof(Elf32_Shdr)
#define PROGSIZE sizeof(Elf32_Phdr)

int
is_elf(Elf32_Ehdr *ehead)
{

	if (IS_ELF(*ehead) && ehead->e_type == ET_EXEC)
		return (1);

	return (0);
}

void
gen_hash(void *buf, int len, unsigned char *hash)
{
	EVP_MD_CTX ctx;
	int olen, i;
	unsigned char tmphash[EVP_MAX_MD_SIZE] = {0};

	EVP_DigestInit(&ctx, EVP_md5());
	EVP_DigestUpdate(&ctx, buf, len);
	EVP_DigestFinal(&ctx, tmphash, &olen);
	EVP_MD_CTX_cleanup(&ctx);

	for (i = 0; i < olen; i++)
		sprintf(&hash[i], "%02x", tmphash[i]);
	hash[olen] = '\0';
}

int
get_section_index(char *secname, Elf32_Shdr *shead,
    Elf32_Ehdr *ehead, char *string_table)
{
	int i;
	for (i = 0; i < ehead->e_shnum; i++)
		if (strcmp(secname, string_table + shead[i].sh_name) == 0)
			return (i);
	return (-1);
}

void
*get_section_entry(int fd, Elf32_Shdr *shead)
{
	void *tmp = NULL;
	if ((tmp = malloc(shead->sh_size)) == NULL)
		return (NULL);
	if (lseek(fd, shead->sh_offset, SEEK_SET) == -1)
		return (NULL);
	if (read(fd, tmp, shead->sh_size) != shead->sh_size)
		return (NULL);

	return (tmp);
}

int
write_signed(int fd , int signed_fd, Elf32_Shdr *shead, Elf32_Phdr *phead,
     Elf32_Ehdr *ehead, char * string_table, char *tmpcert)
{

	int i;
	void *tmp;
	off_t signed_pos;

	if (lseek(signed_fd,
	    sizeof(Elf32_Ehdr) + (sizeof(Elf32_Phdr) * ehead->e_phnum),
	    SEEK_SET) == -1)
		return (1);
	for (i = 0; i < ehead->e_shnum - 1; i++) {
		if (strcmp(".shstrtab", string_table + shead[i].sh_name) == 0) {
			tmp = string_table;
		} else {
			get_section_data(fd,
		    	    shead[i].sh_offset, &tmp, shead[i].sh_size);
		}

		if (lseek(signed_fd, shead[i].sh_offset, SEEK_SET) == -1)
			return (1);
		
		if (write(signed_fd, tmp, shead[i].sh_size) !=
		    shead[i].sh_size)
			return (1);

		free(tmp);
	}
	
	if ((signed_pos = lseek(signed_fd, 0, SEEK_CUR)) == -1)
		return (1);

	if (write(signed_fd, tmpcert, strlen(tmpcert)) != strlen(tmpcert))
		return (1);

	shead[ehead->e_shnum - 1].sh_offset = signed_pos;

	if ((signed_pos = lseek(signed_fd, 0, SEEK_CUR)) == -1)
		return (1);

	ehead->e_shoff = signed_pos;

	if (write(signed_fd, shead, SECSIZE * ehead->e_shnum) !=
	    sizeof(Elf32_Shdr) * ehead->e_shnum)
		return (1);

	/* Write the Elf header and Program Header at the top*/
	if ((signed_pos = lseek(signed_fd, 0, SEEK_SET)) == -1)
		return (1);

	if (write(signed_fd, ehead, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr))
		return (1);

	if (write(signed_fd, phead, PROGSIZE  * ehead->e_phnum) !=
	    sizeof(Elf32_Phdr) * ehead->e_phnum)
		return (1);

	return (0);
}

void
add_section_entry(Elf32_Shdr *shead, Elf32_Ehdr *ehead, int str_pos,
    char *tmpcert)
{
	Elf32_Shdr *shead_tmp = &shead[ehead->e_shnum];

	ehead->e_shnum++;
	/* We don't know the offset for now, we'll fill it out later */
	shead_tmp->sh_type = SHT_NOTE;
	shead_tmp->sh_flags = 0;
	shead_tmp->sh_addr = 0;
	shead_tmp->sh_name = str_pos;
	shead_tmp->sh_size = strlen(tmpcert);
}

int
get_section_data(int fd, int offset, void **buf, int buf_sz)
{
	/* Seek to string table and read its contents */
	if (lseek(fd, offset, SEEK_SET) == -1)
		return (1);

	if ((*buf = malloc(buf_sz)) == NULL)
		return (1);

	if (read(fd, *buf, buf_sz) != buf_sz)
		return (1);

	return (0);
}

int
append_string_table(char **string_table, Elf32_Shdr *shead, char *secname)
{
	char *tmp;

	tmp = realloc(*string_table, shead->sh_size + strlen(secname) + 1);
	if (tmp == NULL)
		return (1);
	*string_table = tmp;

	if (sprintf(*string_table + shead->sh_size, "%s", secname) < 0)
		return (1);

	shead->sh_size += strlen(secname) + 1;

	return (0);
}

int
get_program_entries(int fd, Elf32_Phdr **phead, Elf32_Ehdr ehead)
{

	/* Seek to Section header entries */
	if (lseek(fd, ehead.e_phoff, SEEK_SET) == -1)
		return (1);

	if ((*phead = calloc(ehead.e_phnum, PROGSIZE)) == NULL)
		return (1);

	/* Read Section header entries */
	if (read(fd, *phead, PROGSIZE * ehead.e_phnum) !=
	    PROGSIZE * ehead.e_phnum)
		return (1);

	return (0);
}

int
get_section_entries(int fd, Elf32_Shdr **shead, Elf32_Ehdr ehead)
{

	/* Seek to Section header entries */
	if (lseek(fd, ehead.e_shoff, SEEK_SET) == -1)
		return (1);

	if ((*shead = calloc(ehead.e_shnum + 1, SECSIZE)) == NULL)
		return (1);

	/* Read Section header entries */
	if (read(fd, *shead, SECSIZE * ehead.e_shnum) !=
	    SECSIZE * ehead.e_shnum)
		return (1);

	return (0);
}

void
error()
{

	fprintf(stderr, "err: %s\n", strerror(errno));
}

char
*issue_cert(FILE *fpkey, char *cname,int days)
{
	X509 *x;
	X509_NAME *name = NULL;
	X509_NAME *issuer = NULL;
	EVP_PKEY *pk;
	EVP_PKEY *prv;
	int serial = 0, size = 0;
	RSA *rsa;
	BIO *bmem = BIO_new(BIO_s_mem());
	int bits = 512;
	char *cert = NULL;
	char *tmpcert = NULL;

	prv = PEM_read_PrivateKey(fpkey, NULL, NULL, NULL);
	if (prv == NULL) {
		fprintf(stderr, "Can't read private key\n");
		return (NULL);
	}

	pk = EVP_PKEY_new();
	x = X509_new();
	rsa = RSA_generate_key (bits, RSA_F4, NULL, NULL);
	EVP_PKEY_assign_RSA(pk,rsa);
	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj (X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*days);
	X509_set_pubkey(x, pk);
	name = X509_get_subject_name(x);
	issuer = X509_get_issuer_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cname, -1, -1, 0);
	X509_NAME_add_entry_by_txt(issuer, "CN",
	    MBSTRING_ASC, "IronPort Binary Signer", -1, -1, 0);
	X509_set_issuer_name(x, issuer);
	X509_set_subject_name(x, name);
	X509_sign(x, prv, EVP_md5());
	PEM_write_bio_X509(bmem, x);

	size = BIO_get_mem_data(bmem, &tmpcert);
	tmpcert[size - 1] = '\0';
	if ((cert = malloc(size)) == NULL) {
		EVP_PKEY_free(pk);
		EVP_PKEY_free(prv);
		BIO_free_all(bmem);
       		X509_free(x);
		return NULL;
	}

	strcpy(cert, tmpcert);

	EVP_PKEY_free(pk);
	EVP_PKEY_free(prv);
	BIO_free_all(bmem);
        X509_free(x);

	return (cert);
}
