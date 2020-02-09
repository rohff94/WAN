#include <stdio.h>
#include <limits.h>



int main(int argc, char **argv)
{
	int max = INT_MAX;
	int min = INT_MIN;
	int tmp = INT_MAX;
	
	printf("\tINT Max = %d = %p \n\tINT Min = %d = %p \n",max,max,min,min);
	max = max +1 ;
	printf("\tINT Max %d +1 = %d = %p +1 = %p \n",tmp,max,tmp,min);


}
