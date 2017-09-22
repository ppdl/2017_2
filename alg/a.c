#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define min2(X,Y) ((X) < (Y) ? (X) : (Y))
#define min3(X,Y,Z) (min2(min2(X,Y),Z))

#define max2(X,Y) ((X) > (Y) ? (X) : (Y))
#define max3(X,Y,Z) (max2(max2(X,Y),Z))

typedef struct
{
	int x;
	int y;
}P;

typedef struct
{
	P p1;
	P p2;
}Pair;

int dist(P p1, P p2)
{
	return pow(p1.x-p2.x,2)+pow(p1.y-p2.y,2);
}
int dist(Pair pp)
{
	return pow(pp.p1.x-pp.p2.x)+pow(pp.p1.y-pp.p2.y);
}

Pair CP(P* Px, P* Py)
{
	int size = sizeof(Px)/sizeof(Px[0]);
}


int main()
{
	FILE *fp = fopen("input.txt", "r");

	int numP;
	fscanf(fp, "%d\n", &numP);
	printf("%d\n", numP);

	P* pts = (P*)calloc(numP,sizeof(P));

	for(int i=0; i<numP; i++)
	{
		int x, y;
		fscanf(fp, "%d %d\n", &x, &y);
		pts[i].x = x;
		pts[i].y = y;
	}
	fclose(fp);	//get points from input.txt into pts array

	return ;
}
