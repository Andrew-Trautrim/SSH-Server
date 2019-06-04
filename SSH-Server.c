
/*
 * Author: Andrew Trautrim
 * Remote SSH server using libssh library
 */

#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int input();
int remoteSession(ssh_channel channel);
int verifyHost(ssh_session session);

void closeChannel(const char *errorMesg, ssh_channel channel);
void closeSession(const char *errorMesg, ssh_session session);

int main(int argc, char **argv) {

	char user[50], passwd[50], host[50];

	// User
	fprintf(stdout, "user: ");
	fgets(user, 50, stdin);
	// Password
	fprintf(stdout, "password: ");
	fgets(passwd, 50, stdin);
	// Host
	fprintf(stdout, "host: ");
	fgets(host, 50, stdin);

	// default TCP port is 22
	int port = (argv[1] == NULL) ? 22 : atoi(argv[4]);

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

	// interactive session
	rc = remoteSession(channel);

	ssh_channel_send_eof(channel);
	closeChannel(NULL, channel);
	closeSession(NULL, session);
	return 1;
}

/*
 * non-interactive session
 * runs command remotely in the background
 * prints data recieved
 * sends input to remote device
 */
int remoteSession(ssh_session session) {
	int rc;

	// Create remote shell
	ssh_channel channel = ssh_channel_new(session);
	if (channel == NULL) {
		closeChannel("Unable to create channel", channel);
		return SSH_ERROR;
	}

	// opens channel for command interpreter
	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		closeChannel("Unable to open channel", channel);
		return rc;
	}

	// session initialization
	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK)
		return rc;

	// display directory and contents
	int nbytes, nwritten;
	char buffer[256], cmd[256];

	// non-interactive session
	do {
		fprintf(stdout, ">");
		if (fgets(cmd, 256, stdin) != NULL) {
			rc = ssh_request_exec(channel, cmd);
			if (rc != SSH_OK) {
				closeChannel("Unable to send remote data", channel);
				return rc;
			}
		}

		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
		if (fwrite(buffer, 1, nbytes, stdout) != nbytes) {
			closeChannel("Unable to display remote data", channel);
			return SSH_ERROR;
		}
	} while (nbytes > 0);
	
	if (nbytes < 0) {
		closeChannel("Unable to read remote data", channel);
		return SSH_ERROR;
	}

	closeChannel(NULL, channel);
	return SSH_OK;
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
		fprintf(stdout, "%s: %s\n", errorMesg, ssh_get_error(channel));
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
		fprintf(stdout, "%s: %s\n", errorMesg, ssh_get_error(session));
	ssh_disconnect(session);
	ssh_free(session);
	return;
}
