#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv) {
	
	ssh_session currSession = ssh_new();
	if(!currSession)
		return -1;

	int rc;
	char *passwd;

	return 1;
}
