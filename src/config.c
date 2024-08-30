/*
 * config.c
 *
 * Copyright (c) 2024 Lukasz Krawiec
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <search.h>

#ifndef SYSLOG_NAMES
#define SYSLOG_NAMES
#endif

#ifndef __USE_MISC
#define __USE_MISC
#endif

#include <syslog.h>

#include "config.h"
#include "utils.h"

#ifndef NSS_MTL_CONFIG_FILE
#define NSS_MTL_CONFIG_FILE "/etc/nss_mtl.conf"
#endif

#ifndef NSS_MTL_EXCLUDED_USERS_SIZE
#define NSS_MTL_EXCLUDED_USERS_SIZE 32
#endif

#define KEY_VALUE_DELIMITERS "= \t\r\n"
#define COMMA_SEPARATED_VALUE_DELIMITERS "=, \t\r\n"

static void* nss_mtl_config_ignored_users_parse(void);
static void nss_mtl_config_ignored_users_free(void* node);
static int nss_mtl_config_log_level_parse(const char* level);

/* implementation */

void* nss_mtl_config_ignored_users_parse(void) {
	void* tree = NULL;

	/* Note: we rely here on internal buffer of strtok() function */
	char* token = NULL;
	while ((token = strtok(NULL, COMMA_SEPARATED_VALUE_DELIMITERS)) != NULL) {
		char* name = strdup(token);
		char** node = tsearch(name, &tree, nss_mtl_utils_str_cmp);
		if (node == NULL) {
			syslog(LOG_ERR, "%s: cannot allocate buffer for ignored_users list", __func__);
			tdestroy(tree, free);
			return NULL;
		} else if (*node != name) {
			syslog(LOG_WARNING, "%s: duplicate ignored user detected: %s", __func__, name);
			free(name);
		}
	}

	return tree;
}

void nss_mtl_config_ignored_users_free(void* node) {
	(void)node;
	/* do nothing */
}

int nss_mtl_config_log_level_parse(const char* level) {
	int ret = -1;
	for (int i = 0; prioritynames[i].c_name != NULL; ++i) {
		if (strcmp(level, prioritynames[i].c_name) == 0) {
			ret = prioritynames[i].c_val;
			break;
		}
	}

	if (ret < 0) {
		syslog(LOG_WARNING, "%s: unknown log_level value: %s", __func__, level);
		ret = LOG_INFO;
	}

	return ret;
}

nss_mtl_config_t* nss_mtl_config_parse(const char* path) {
	if (path == NULL) {
		path = NSS_MTL_CONFIG_FILE;
	}

	FILE* f = fopen(path, "r");
	if (f == NULL) {
		syslog(LOG_ERR, "%s: cannot open config file %s: %m", __func__, path);
		return NULL;
	}

	char buffer[BUFSIZ];
	void* ignored_users = NULL;
	size_t ignored_users_size = 0;

	nss_mtl_config_t* config = malloc(sizeof(nss_mtl_config_t));
	if (config == NULL) {
		syslog(LOG_ERR, "%s: could not allocate config: %m", __func__);
		return NULL;
	}
	memset(config, 0, sizeof(nss_mtl_config_t));

	char* token = NULL;
	while (fgets(buffer, sizeof(buffer), f) != NULL) {
		/* ignore empty lines and comments */
		if (buffer[0] == '#' || isspace((unsigned char)buffer[0])) {
			continue;
		}
		token = strtok(buffer, KEY_VALUE_DELIMITERS);
		if (strcmp(token, "log_level") == 0) {
			token = strtok(NULL, KEY_VALUE_DELIMITERS);
			if (token == NULL) {
				syslog(LOG_WARNING, "%s: missing value for log_level key", __func__);
			} else {
				config->log_level = nss_mtl_config_log_level_parse(token);
			}
		} else if (strcmp(token, "target_user") == 0) {
			token = strtok(NULL, KEY_VALUE_DELIMITERS);
			if (token == NULL) {
				syslog(LOG_WARNING, "%s: missing value for target_user key", __func__);
			} else {
				config->target_user = strdup(token);
			}
		} else if (strcmp(token, "ignored_users") == 0) {
			ignored_users = nss_mtl_config_ignored_users_parse();
			if (ignored_users != NULL) {
				twalk_r(ignored_users, nss_mtl_utils_tree_size_calc, &ignored_users_size);
			}
		}
	}

	if (config->target_user == NULL || strlen(config->target_user) == 0) {
		syslog(LOG_ERR, "%s: target_user not defined, cannot continue", __func__);
		nss_mtl_config_free(config);
		return NULL;
	}

	config->ignored_users = nss_mtl_utils_list_alloc(ignored_users_size);
	if (config->ignored_users == NULL) {
		syslog(LOG_ERR, "%s: could not allocate buffer for ignored_users list of size %ld: %m", __func__, ignored_users_size);
		nss_mtl_config_free(config);
		return NULL;
	}

	twalk_r(ignored_users, nss_mtl_utils_list_fill, config->ignored_users);
	tdestroy(ignored_users, nss_mtl_config_ignored_users_free);

	return config;
}

void nss_mtl_config_free(nss_mtl_config_t* config) {
	nss_mtl_utils_list_free(config->ignored_users);
	free(config->target_user);
	free(config);
}