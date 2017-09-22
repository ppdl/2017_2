#include <stdio.h>

int main()
{
	FILE *fp = fopen("packetsniff.c", "r");
	FILE *out = fopen("./img/here.c", "w");
	int count = 0;
	while(!feof(fp))
	{
		char c = fgetc(fp);
		printf("%c ", c);
		fputc(c, out);
		{
			printf("\n%d: ", count);
		}
		//if(count > 800) break;
	}
}
