#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

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
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	nss_mtl_config_t* config = nss_mtl_config_parse(argv[1]);
	print_config(config);

	nss_mtl_config_free(config);

	nss_mtl_utils_list_t* users = nss_mtl_utils_users_get();
	printf("Logged in users =");
	print_list(users);

	return EXIT_SUCCESS;
}