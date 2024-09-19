#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>

#include "src/mtl.h"
#include "src/config.h"
#include "src/utils.h"

static void print_list(nss_mtl_utils_list_t* lst) {
	for (size_t i = 0; i < lst->filled; ++i) {
		printf(" %s%s", lst->items[i], (i + 1 >= lst->filled) ? "" : ",");
	}
	printf("\n");
}

static void print_config(nss_mtl_config_t* config) {
	assert(config != NULL);
	printf("Configuration:\n");
	printf("log_level = %d\n", config->log_level);
	printf("target_user = %s\n", config->target_user);
	printf("ignored_users =");
	print_list(config->ignored_users);
	printf("ignored_execs =");
	print_list(config->ignored_execs);
}

int main(int argc, char* argv[]) {
	char* conf = NULL;
	char* user = NULL;
	char* group = NULL;

	int opt = 0;
	while ((opt = getopt(argc, argv, "c:u:g:")) != -1) {
		switch (opt) {
		case 'c':
			conf = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'g':
			group = optarg;
			break;
		default:
			fprintf(stderr, "Usage: %s [-c <config_file>] [-u <username>] [-g groupname]\n", argv[0]);
			return EXIT_FAILURE;
		}
	}


	nss_mtl_utils_list_t* users = nss_mtl_utils_users_get();
	printf("Logged in users =");
	print_list(users);
	nss_mtl_utils_list_free(users);

	if (conf != NULL) {
		nss_mtl_config_t* config = nss_mtl_config_parse(conf);
		print_config(config);
		nss_mtl_config_free(config);
	}

	char buffer[BUFSIZ];
	int errnop = 0;

	if (user != NULL) {
		struct passwd pw;
		enum nss_status status = _nss_mtl_getpwnam_r(user, &pw, buffer, BUFSIZ, &errnop);
		if (status != NSS_STATUS_SUCCESS) {
			fprintf(stderr, "Cannot acquire user info: %d (%d)\n", status, errnop);
		} else {
			printf("user %s, uid = %u, homedir = %s, shell = %s\n", pw.pw_name, pw.pw_uid, pw.pw_dir, pw.pw_shell);
		}
	}

	if (group != NULL) {
		struct group g;
		enum nss_status status = _nss_mtl_getgrnam_r(group, &g, buffer, BUFSIZ, &errnop);
		if (status != NSS_STATUS_SUCCESS) {
			fprintf(stderr, "Cannot acquire group info: %d (%d)\n", status, errnop);
		} else {
			printf("group %s, members: ", g.gr_name);
			for (size_t i = 0; g.gr_mem[i] != NULL; ++i) {
				printf("%s%s", g.gr_mem[i], (g.gr_mem[i+1] != NULL) ? ", " : "");
			}
			printf("\n");
		}
	}

	return EXIT_SUCCESS;
}