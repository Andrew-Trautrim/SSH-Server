#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv) {
	
	// checks for proper input
	if(argc != 4) {
		printf("Usage: %s <user> <passwd> <host>\n", argv[0]);
		return -1;
	}
	char *user = argv[1];
	char *passwd = agv[2];
	char *host = argv[3];
	// default TCP port is 22
	int port = (argv[4] == NULL) ? 22 : atoi(argv[4]);

	// create new session
	ssh_session currSession = ssh_new();
	if(currSession == NULL) {
		printf("Unable to create session\n");
		return -1;
	}
	// modify session settings
	ssh_options_set(currSession, SSH_OPTIONS_HOST, host);
	ssh_options_set(currSession, SSH_OPTIONS_PORT, port);
	ssh_options_set(currSession, SSH_OPTIONS_USER, user);

	// connect to server
	int rc = ssh_connect(currSession);
	if (rc != SSH_OK) {
		printf("Unable to connect to %s: %s\n", host, ssh_get_error(currSession));
		ssh_free(currSession);
		return -1;
	}

	// host verification
	if(verify_knownhost(currSession) < 0) {
		ssh_disconnect(currSession);
		ssh_free(currSession);
		return -1;
	}

	// user authentication
	rc = ssh_userauth_password(currSession, NULL, passwd);
	if (rc != SSH_AUTH_SUCCESS) {
		printf("Password authentication error: %s", ssh_get_error(currSession));
		ssh_disconnect(currSession);
		ssh_free(currSession);
		return -1;
	}

	// TODO

	ssh_disconnect(currSession);
	ssh_free(currSession);

	return 1;
}
