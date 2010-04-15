#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "signer_common.h"

char *secname = "cert";

int main(int argc, char *argv[])
{
	int fd, signed_fd;	/* fd for unsigned exec & newly signed exec */
	Elf32_Ehdr ehead;	/* elf head */
	Elf32_Shdr *shead;	/* section head array */
	Elf32_Phdr *phead;	/* Program head array */
	char *string_table;	/* String table to hold .text, .bss etc.. */
	char *tmpcert;
	char *ispath;
	int secindex;
	FILE *fpkey;
	int days;
	void *textseg;		/* For hashing the .text segment */
	unsigned char hash[EVP_MAX_MD_SIZE] = {0}; /* Hold the hash string */
	char signed_fname[_POSIX_NAME_MAX];

	if (argc != 4) {
		fprintf (stderr, "Incorrect number of arguments\n");
		fprintf (stdout, "signer <exec_file> <key_file> <days>\n");
		return 1;
	}

	if ((days = strtol(argv[3], NULL, 10)) == 0) {
		fprintf(stderr, "Incorrect days argument\n");
		return 1;
	}

	if ((fpkey = fopen(argv[2], "r")) == NULL) {
		fprintf(stderr, "Can't open private key file\n");
		return 1;
	}

	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		fprintf(stderr, "Can't open executable\n");
		return 1;
	}

	/* If we are given a full path, truncate and take the filename only.
	* Make sure to increment by one if we find a / because strrchr
	* points to '/' and not the character following it.
	*/
	if ((ispath = strrchr(argv[1], '/')) == NULL)
		ispath = argv[1];
	else
		ispath++;

	if (sprintf(signed_fname, "signed_%s", ispath) < 0)
		error();

	/* Read elf32 header */
	if (read(fd, &ehead, sizeof (Elf32_Ehdr)) != sizeof (Elf32_Ehdr))
		error();

	if (!is_elf(&ehead)) {
		fprintf(stderr, "File is not an executable binary\n");
		return 1;
	}

	if ((signed_fd =
	    open(signed_fname, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU)) == -1)
		error();

	/* *PSST* We also allocate additonal section when retrieving them*/
	if (get_section_entries(fd, &shead, ehead))
		error();
	if (get_program_entries(fd, &phead, ehead))
		error();

	/* Get string table section data */
	if (get_section_data(fd, shead[ehead.e_shstrndx].sh_offset,
	    (void **)&string_table, shead[ehead.e_shstrndx].sh_size))
		error();

	secindex = get_section_index(".text", shead, &ehead, string_table);
	if (secindex == -1) {
		fprintf(stderr, "Can't find .text segment\n");
		return 1;
	}
	if ((textseg = get_section_entry(fd, &shead[secindex])) == NULL)
		error();

	gen_hash(textseg, shead[secindex].sh_size, hash);

	if (append_string_table(&string_table,
	    &shead[ehead.e_shstrndx], secname))
		error();

	if ((tmpcert = issue_cert(fpkey, hash, days)) == NULL) {
		fprintf(stderr, "Can't generate certificate\n");
		return 1;
	}
	/*
	  We can only call add_section_entry once, else we'll start overflowing
	  because we only allocated one additonal section for the .cert
	*/
	add_section_entry(shead, &ehead,
	    shead[ehead.e_shstrndx].sh_size - strlen(secname) - 1, tmpcert);

	/* write_signed frees string_table after it is done with it */
	if (write_signed(fd, signed_fd, shead,
	    phead, &ehead, string_table, tmpcert))
		error();

	printf("%s successfully signed, with filename %s\n",
	    argv[1], signed_fname);

	free(shead);
	free(phead);
	free(textseg);
	free(tmpcert);
	close(fd);	
	close(signed_fd);	
	fclose(fpkey);

	return 0;
}
