#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	long	ret;
	char	*dummy;

	ret = strtol(argv[2], &dummy, 10);

	while(ret-- > 0)
		printf("%s\n", argv[1]);

	return 0;
}
