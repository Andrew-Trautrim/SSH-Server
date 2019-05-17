#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv) {
	
	// checks for proper input
	if(argc != 4) {
		printf("Usage: %s <user> <passwd> <c2host>\n", argv[0]);
		return -1;
	}
	char *user = argv[1];
	char *passwd = agv[2];
	char *host = argv[3];
	// default TCP port is 22
	int port = (argv[4] == NULL) ? 22 : atoi(argv[4]);

	// creates new session
	ssh_session currSession = ssh_new();
	if(currSession == NULL) {
		printf("Unable to create session\n");
		return -1;
	}
	// modify session settings
	ssh_options_set(currSession, SSH_OPTIONS_HOST, argv[3]);
	ssh_options_set(currSession, SSH_OPTIONS_PORT, 22);
	ssh_options_set(currSession, SSH_OPTIONS_USER, argv[1]);

	int rc = ssh_connect(currSession);
	// Verifys the host if it is not yet registered in the known hosts file
	if(ssh_session_is_known_server() != SSH_KNOWN_HOSTS_OK) {
		char input;
		printf("Unknown host\n");
		do {
			printf("Verify host validity [Y/N]: ");
			input = getc(stdin);
		} while (input != 'Y' || input != 'N')
		if (input == 'Y')
			ssh_write_knownhost(currSession);
		else {
			ssh_disconnect(currSession);
			ssh_free(currSession);
			return -1;
		}
	}
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
