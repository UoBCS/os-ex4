#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{

    
	int option = 0; 
	if(argc <2)
	{
		printf("Usage:\n");
		printf(" %s L            to display rules in kern.log\n", argv[0]);
		printf(" %s W <filename> to load new rules\n", argv[0]);
		return 1;
	}
	else {
		if(strcmp(argv[1],"L")==0){
			printf("Print current policy\n");
			// TODO: Complete me
			return 0;
		} else {
			if(strcmp(argv[1],"W")==0){
				printf("Reading commands\n");
				// TODO: Complete me
				return 0;
			} else{
				printf("Usage:\n ");
				printf("+L to display rules in kern.log\n");
				printf("+\n");
				printf("%s",argv[1]);
				return 1;
			}
		}
	}
}
