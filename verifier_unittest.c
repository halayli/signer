#include <stdio.h>
#include "verifier.h"


int main(int argc, char *argv[])
{
	 if (!verify_binary(argv[1], NULL))
		printf ("%s signed\n", argv[1]);

	return 0;
}
