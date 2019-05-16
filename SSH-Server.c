#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv) {
	
	/* checks for proper input */
	if(argc != 4) {
		printf("Usage: %s <user> <passwd> <c2host>\n", argv[0]);
		return -1;
	}
	char *passwd = agv[2];

	/* creates new session */
	ssh_session currSession = ssh_new();
	if(!currSession)
		return -1;
	/* modify session settings */
	ssh_options_set(currSession, SSH_OPTIONS_HOST, argv[3]);
	ssh_options_set(currSession, SSH_OPTIONS_PORT, 443);
	ssh_options_set(currSession, SSH_OPTIONS_USER, argv[1]);

	int rc = ssh_connect(currSession);
	if(verify_knownhost(currSession) < 0) {
		ssh_disconnect(currSession);
		ssh_free(currSession);
		return -1;
	}

	rc = ssh_userauth_password(currSession, NULL, passwd);
	ssh_disconnect(currSession);
	ssh_free(currSession);

	return 1;
}
