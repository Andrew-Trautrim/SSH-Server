
/*
 * Author: Andrew Trautrim
 * Remote SSH server using libssh library
 */

#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int authenticate_password(ssh_session session, char *user, char *password);
int authenticate_public_key(ssh_session session, char *user, char *password);
int remote_session(ssh_session session);
int verify_host(ssh_session session);

void close_channel(const char *error_mesg, ssh_channel channel);
void close_session(const char *error_mesg, ssh_session session);

int main(int argc, char **argv) {

	char user[50], host[50];	
	// User
	fprintf(stdout, "User: ");
	fgets(user, 50, stdin);
	// Password
	char *password = getpass("Password: ");
	// Host
	fprintf(stdout, "Host: ");
	fgets(host, 50, stdin);
	// Private key passphrase
	char *passphrase = getpass("Passphrase: ");

	
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
		close_session("Unable to connect to host", session);
		return -1;
	}

	// host verification
	if(verify_host(session) == -1) {
		close_session("Unable to verify host", session);
		return -1;
	}

	// public key authentication
	if (authenticate_public_key(session, user, passphrase) == SSH_AUTH_ERROR)
		return -1;
	// password authentication
	if (authenticate_password(session, user, password) == SSH_AUTH_ERROR)
		return -1;

	// non-interactive session
	rc = remote_session(session);

	close_session(NULL, session);
	return 1;
}

/*
 * authenticates network through given password
 */
int authenticate_password(ssh_session session, char *user, char *password) {
	int rc = ssh_userauth_password(session, user, password);
	if (rc != SSH_AUTH_SUCCESS) {
		close_session("Password authentication error", session);
		return SSH_ERROR;
	}
	return rc;
}

/*
 * authenticates network over public key
 */
int authenticate_public_key(ssh_session session, char *user, char *passphrase) {
	ssh_key pub_key = malloc(sizeof(ssh_key));
	ssh_key priv_key = malloc(sizeof(ssh_key));
	int rc;
	
	// imports public key from file
	rc = ssh_pki_import_pubkey_file("~/.ssh/pub_key.pub", &pub_key);
	if (rc != SSH_OK) {
		// returns error is unable to authenticate

		close_session("Unable to retrieve public key", session);
		return SSH_ERROR;
	}

	// determines if authentication with the public key is possible
	rc = ssh_userauth_try_publickey(session, NULL, pub_key);
	if (rc != SSH_AUTH_SUCCESS && rc != SSH_AUTH_PARTIAL) {
		ssh_key_free(pub_key);
		ssh_key_free(priv_key);
		close_session("Public key authentication error", session);
		return SSH_ERROR;
	}

	// retrieves the private key
	rc = ssh_pki_import_privkey_file("~/.ssh/pub_key", passphrase, NULL, NULL, &priv_key);
	if (rc != SSH_OK) {
		ssh_key_free(pub_key);
		ssh_key_free(priv_key);
		close_session("Unable to retrieve private key", session);
		return SSH_ERROR;
	}

	// authenticates prublic/private key pair
	rc = ssh_userauth_publickey(session, user, priv_key); 
	if (rc != SSH_AUTH_SUCCESS && rc != SSH_AUTH_PARTIAL) {
		ssh_key_free(pub_key);
		ssh_key_free(priv_key);
		close_session("Publie/Private key authentication error", session);
		return SSH_ERROR;
	}

	ssh_key_free(pub_key);
	ssh_key_free(priv_key);
	return rc;
}

/*
 * non-interactive session
 * runs command remotely in the background
 * prints data recieved
 * sends input to remote device
 */
int remote_session(ssh_session session) {
	int rc;

	// Creating remote shell
	fprintf(stdout, "creating remote shell...\n");
	ssh_channel channel = ssh_channel_new(session);
	if (channel == NULL) {
		close_channel("Unable to create channel", channel);
		return SSH_ERROR;
	}

	// opens channel for command interpreter
	fprintf(stdout, "opening channel...\n");
	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		close_channel("Unable to open channel", channel);
		return rc;
	}

	// session initialization
	fprintf(stdout, "requesting shell...\n");
	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK)
		return rc;

	// display directory and contents
	int nbytes, nwritten;
	char buffer[256], cmd[256];

	fprintf(stdout, "Session:\n");
	// non-interactive session
	do {
		fprintf(stdout, ">");
		if (fgets(cmd, 256, stdin) != NULL) {
			rc = ssh_channel_request_exec(channel, cmd);
			if (rc != SSH_OK) {
				close_channel("Unable to send remote data", channel);
				return rc;
			}
		}

		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
		if (fwrite(buffer, 1, nbytes, stdout) != nbytes) {
			close_channel("Unable to display remote data", channel);
			return SSH_ERROR;
		}
	} while (nbytes > 0);
	
	if (nbytes < 0) {
		close_channel("Unable to read remote data", channel);
		return SSH_ERROR;
	}

	close_channel(NULL, channel);
	return SSH_OK;
}

/*
 * Verifies validity of host
 * checks internal known hosts file
 */
int verify_host(ssh_session session) {

	char input;
	switch (ssh_session_is_known_server(session)) {
		case SSH_KNOWN_HOSTS_OK:
			return 1;
		case SSH_KNOWN_HOSTS_NOT_FOUND:
			fprintf(stderr, "Host not listed in known hosts file.\n");
			/* carry on to SSH_KNWON_HOSTS_UNKNOWN */
		case SSH_KNOWN_HOSTS_UNKNOWN:
			do {
				fprintf(stderr, "Verify host [Y/N]: ");
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
void close_channel(const char* error_mesg, ssh_channel channel) {
	if (error_mesg != NULL)
		fprintf(stdout, "%s: %s\n", error_mesg, ssh_get_error(channel));
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return;
}

/*
 * prints error message if needed
 * disconnects/deallocates ssh session
 */
void close_session(const char *error_mesg, ssh_session session) {
	if (error_mesg != NULL) 
		fprintf(stdout, "%s: %s\n", error_mesg, ssh_get_error(session));
	ssh_disconnect(session);
	ssh_free(session);
	return;
}
