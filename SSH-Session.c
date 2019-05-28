
/*
 * Author: Andrew Trautrim
 * Remote SSH server using libssh library
 */

#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>

int verifyHost(ssh_session session);

void closeChannel(const char *errorMesg, ssh_channel channel);
void closeSession(const char *errorMesg, ssh_session session);

int main(int argc, char **argv) {
	
	// checks for proper input
	if(argc != 4 && argc != 5) {
		printf("Usage: %s <user> <passwd> <host> [port]\n", argv[0]);
		return -1;
	}

	char *user = argv[1];
	char *passwd = argv[2];
	char *host = argv[3];
	// default TCP port is 22
	int port = (argv[4] == NULL) ? 22 : atoi(argv[4]);

	// create new session
	ssh_session session = ssh_new();
	if(session == NULL) {
		printf("Unable to create session: %s\n", ssh_get_error(session));
		return -1;
	}

	// modify session settings
	ssh_options_set(session, SSH_OPTIONS_HOST, host);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);
	ssh_options_set(session, SSH_OPTIONS_USER, user);

	// connect to server
	int rc = ssh_connect(session);
	// verify connection
	if (rc != SSH_OK) {
		closeSession("Unable to connect to host", session);
		return -1;
	}

	// host verification
	if(verifyHost(session) == -1) {
		closeSession("Unable to verify host", session);
		return -1;
	}

	// password authentication
	rc = ssh_userauth_password(session, user, passwd);
	if (rc != SSH_AUTH_SUCCESS) {
		closeSession("Password authentication error", session);
		return -1;
	}

	// Create remote shell
	ssh_channel channel = ssh_channel_new(session);
	if (channel == NULL) {
		closeChannel("Unable to create channel", channel);
		closeSession(NULL, session);
		return -1;
	}
	// opens channel to create command interpreter
	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		closeChannel("Unable to open channel", channel);
		closeSession(NULL, session);
		return -1;
	}

	// interactive session
	while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
		
	}

	// TODO
	// Open remote shell / pass remote command

	closeChannel(NULL, channel);
	closeSession(NULL, session);
	return 1;
}

/*
 * Verifies validity of host
 * checks internal known hosts file
 */
int verifyHost(ssh_session session) {

	switch (ssh_session_is_known_server(session)) {
		case SSH_KNOWN_HOSTS_OK:
			return 1;
		case SSH_KNOWN_HOSTS_NOT_FOUND:
			fprintf(stderr, "Host not listed in known hosts file.\n");
			/* carry on to SSH_KNWON_HOSTS_UNKNOWN */
		case SSH_KNOWN_HOSTS_UNKNOWN:
			fprintf(stderr, "Unknown server.\n");
			char input;
			do {
				fprintf(stderr, "Verify and add to known hosts file [Y/N]: ");
				input = fgetc(stdin);
			} while (input != 'Y' && input != 'N');
			return (input == 'Y') ? 1 : -1;
		default:
			fprintf(stderr, "Error: %s\n", ssh_get_error(session));
			return -1;
	}
	return -1;
}

/*
 * prints error message if needed
 * disconnects/deallocates ssh channel
 */
void closeChannel(const char* errorMesg, ssh_channel channel) {
	if (errorMesg != NULL)
		printf("%s: %s\n", errorMesg, ssh_get_error(channel));
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return;
}

/*
 * prints error message if needed
 * disconnects/deallocates ssh session
 */
void closeSession(const char *errorMesg, ssh_session session) {
	if (errorMesg != NULL) 
		printf("%s: %s\n", errorMesg, ssh_get_error(session));
	ssh_disconnect(session);
	ssh_free(session);
	return;
}
