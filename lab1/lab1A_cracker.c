#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv){
	if(argc<=1){
		printf("Usage: %s name\n",argv[0]);
		exit(1);
	}
	char *username=argv[1];
	int serial = ((int)username[3] ^ 0x1337) + 0x5eeded;
	int index=0;
	while(index < strlen(username)){
		if(username[index]<' ')
			return 1;
		serial += ((int)username[index] ^ serial) % 0x539;
		index=index+1;
	}
	printf("Serial: %d\n",serial);
	return 0;
}

