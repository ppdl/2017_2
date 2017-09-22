#include <stdio.h>

int main()
{
	FILE *fp = fopen("testimg.jpeg", "r");
	FILE *out = fopen("testout.jpeg", "w");
	int count = 0;
	while(!feof(fp))
	{
		char c = fgetc(fp);
		printf("%c ", c);
		fputc(c, out);
		count++;
		if(count % 8 == 0) printf("  ");
		if(count % 32 == 0)
		{
			printf("\n%d: ", count);
		}
		//if(count > 800) break;
	}
}
