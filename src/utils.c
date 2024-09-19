/*
 * utils.c
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
#include <string.h>
#include <search.h>

#include <sys/types.h>
#include <utmpx.h>
#include <syslog.h>
#include <pwd.h>

#include "utils.h"

void nss_mtl_utils_list_fill(const void* node, VISIT which, void* closure);
static void nss_mtl_utils_active_users_free(void* node);

static void* nss_mtl_utils_local_users_get(void);
static void nss_mtl_utils_local_users_free(void* users);

/* implementation */

static int nss_mtl_utils_log_level = LOG_INFO;

void nss_mtl_utils_tree_size_calc(const void* node, VISIT which, void* closure) {
	(void)node;

	if (which != postorder && which != leaf) {
		return;
	}

	size_t* size = (size_t*)closure;
	*size += 1;
}

void nss_mtl_utils_list_fill(const void* node, VISIT which, void* closure) {
	if (which != postorder && which != leaf) {
		return;
	}

	nss_mtl_utils_list_t* lst = (nss_mtl_utils_list_t*)closure;
	char** value = (char**)node;

	lst->items[lst->filled++] = *value;
}

void nss_mtl_utils_active_users_free(void* node) {
	/* do nothing */
	(void)node;
}

void* nss_mtl_utils_local_users_get() {
	void* local = NULL;

	FILE* f = fopen(NSS_MTL_PASSWD_FILE, "r");
	if (f == NULL) {
		nss_mtl_utils_log(LOG_ERR, "%s: failed to open %s for reading: %m", __func__, NSS_MTL_PASSWD_FILE);
		return NULL;
	}

	struct passwd* pw = NULL;
	while ((pw = fgetpwent(f)) != NULL) {
		char* name = strdup(pw->pw_name);
		char** node = tsearch(name, &local, nss_mtl_utils_str_cmp);
		if (node == NULL || *node != name) {
			free(name);
		}
	}

	fclose(f);

	return local;
}

void nss_mtl_utils_local_users_free(void* users) {
	tdestroy(users, free);
}

int nss_mtl_utils_str_cmp(const void* a, const void* b) {
	const char* sa = a;
	const char* sb = b;
	return strcmp(sa, sb);
}

int nss_mtl_utils_strptr_cmp(const void* a, const void* b) {
	const char* const* ptr_a = a;
	const char* const* ptr_b = b;

	return strcmp(*ptr_a, *ptr_b);
}

nss_mtl_utils_list_t* nss_mtl_utils_users_get(void) {
	void* local = nss_mtl_utils_local_users_get();

	setutxent();

	void* active = NULL;
	struct utmpx* rec = NULL;
	while ((rec = getutxent()) != NULL) {
		if (rec->ut_type != USER_PROCESS) {
			continue;
		}
		if (tfind(rec->ut_user, &local, nss_mtl_utils_str_cmp) != NULL) {
			nss_mtl_utils_log(LOG_DEBUG, "%s: ignoring local user %s", __func__, rec->ut_user);
			continue;
		}
		char* name = strdup(rec->ut_user);
		char** node = tsearch(name, &active, nss_mtl_utils_str_cmp);
		if (node == NULL) {
			nss_mtl_utils_log(LOG_ERR, "%s: cannot allocate buffer for user %s", __func__, name);
			free(name);
			nss_mtl_utils_local_users_free(local);
			return NULL;
		} else if (*node != name) {
			/* username not unique */
			free(name);
		} else {
			nss_mtl_utils_log(LOG_DEBUG, "%s: found user %s", __func__, name);
		}
	}

	endutxent();

	nss_mtl_utils_local_users_free(local);

	size_t size = 0;
	twalk_r(active, nss_mtl_utils_tree_size_calc, &size);
	nss_mtl_utils_log(LOG_DEBUG, "%s: found %lu active users", __func__, size);

	nss_mtl_utils_list_t* lst = nss_mtl_utils_list_alloc(size);;
	if (lst == NULL) {
		tdestroy(active, nss_mtl_utils_active_users_free);
		return NULL;
	}

	twalk_r(active, nss_mtl_utils_list_fill, lst);
	tdestroy(active, nss_mtl_utils_active_users_free);

	return lst;
}

nss_mtl_utils_list_t* nss_mtl_utils_list_alloc(size_t nmemb) {
	const size_t size = sizeof(nss_mtl_utils_list_t) + nmemb * sizeof(char*);
	nss_mtl_utils_list_t* res = malloc(size);
	if (res == NULL) {
		nss_mtl_utils_log(LOG_ERR, "%s: cannot allocate buffer of size %ld", __func__, size);
	} else {
		res->size = nmemb;
		res->filled = 0;
		memset(res->items, 0, nmemb * sizeof(char*));
	}

	return res;
}

void nss_mtl_utils_list_free(nss_mtl_utils_list_t* lst) {
	if (lst == NULL) {
		return;
	}

	for (size_t i = 0; i < lst->filled; ++i) {
		free(lst->items[i]);
	}

	free(lst);
}

void nss_mtl_utils_log_setup(int log_level) {
	nss_mtl_utils_log_level = log_level;
}

void nss_mtl_utils_log(int level, const char* fmt, ...) {
	if (level <= nss_mtl_utils_log_level) {
		va_list args;
		va_start(args, fmt);
		vsyslog(level, fmt, args);
		va_end(args);
	}
}