/*
 * mtl.c
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
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include "mtl.h"
#include "config.h"
#include "utils.h"

extern char* __progname;

#ifndef NSS_MTL_GROUP_FILE
#define NSS_MTL_GROUP_FILE "/etc/group"
#endif

typedef struct {
	uid_t uid;
	gid_t gid;
	char* gecos;
	char* homedir_root;
	char* shell;
} nss_mtl_user_info_t;

static char* nss_mtl_alloc_static(char** buffer, size_t* buflen, size_t size);
static bool nss_mtl_user_ignored(const nss_mtl_config_t* config, const char* name);
static bool nss_mtl_exec_ignored(const nss_mtl_config_t* config, const char* name);
static char* nss_mtl_parent_dir(const char* path);
static nss_mtl_user_info_t* nss_mtl_user_info_read(const char* name);
static void nss_mtl_user_info_free(nss_mtl_user_info_t* info);
static bool nss_mtl_group_adapt(nss_mtl_config_t* config, nss_mtl_utils_list_t* active_users, struct group* dst, const struct group* src, char* buffer, size_t buflen);
static long nss_mtl_today();

static FILE* nss_mtl_group = NULL;
static nss_mtl_config_t* nss_mtl_config = NULL;
static nss_mtl_utils_list_t* nss_mtl_active_users = NULL;
static char nss_mtl_current_user[LOGIN_NAME_MAX + 1] = { '\0' };

/* implementation */

char* nss_mtl_alloc_static(char** buffer, size_t* buflen, size_t size) {
	if (buffer == NULL || buflen == NULL || *buflen < size) {
		nss_mtl_utils_log(LOG_WARNING, "%s: cannot allocate buffer of size %ld", __func__, size);
		return NULL;
	}

	char* res = *buffer;
	*buffer += size;
	*buflen -= size;

	return res;
}

bool nss_mtl_user_ignored(const nss_mtl_config_t* config, const char* name) {
	assert(config != NULL);
	assert(name != NULL);

	if (strcmp(config->target_user, name) == 0) {
		return true;
	}

	const nss_mtl_utils_list_t* ignored = config->ignored_users;
	if (bsearch(&name, ignored->items, ignored->filled, sizeof(char*), nss_mtl_utils_strptr_cmp) != NULL) {
		return true;
	}

	FILE* f = fopen(NSS_MTL_PASSWD_FILE, "r");
	struct passwd* entry = NULL;
	while ((entry = fgetpwent(f)) != NULL) {
		if (entry->pw_name == NULL) {
			nss_mtl_utils_log(LOG_WARNING, "%s: found empty username in passwd file", __func__);
			continue;
		}
		if (strcmp(entry->pw_name, name) == 0) {
			nss_mtl_utils_log(LOG_DEBUG, "%s: ignoring local user %s", __func__, name);
			break;
		}
	}

	fclose(f);

	return entry != NULL;
}

bool nss_mtl_exec_ignored(const nss_mtl_config_t* config, const char* name) {
	assert(config != NULL);

	const nss_mtl_utils_list_t* ignored = config->ignored_execs;
	return bsearch(&name, ignored->items, ignored->filled, sizeof(char*), nss_mtl_utils_strptr_cmp) != NULL;
}

char* nss_mtl_parent_dir(const char* path) {
	assert(path != NULL);

	char* last_slash = strrchr(path, '/');
	if (last_slash == NULL) {
		return strdup(path);
	} else {
		return strndup(path, last_slash - path);
	}
}

nss_mtl_user_info_t* nss_mtl_user_info_read(const char* name) {
	assert(name != NULL);

	FILE* f = fopen(NSS_MTL_PASSWD_FILE, "r");
	if (f == NULL) {
		nss_mtl_utils_log(LOG_ERR, "%s: failed to open %s for reading: %m", __func__, NSS_MTL_PASSWD_FILE);
		return NULL;
	}

	nss_mtl_user_info_t* info = NULL;
	struct passwd* entry = NULL;
	while ((entry = fgetpwent(f)) != NULL) {
		if (entry->pw_name == NULL) {
			nss_mtl_utils_log(LOG_WARNING, "%s: found empty username in passwd file", __func__);
			continue;
		}
		if (strcmp(entry->pw_name, name) == 0) {
			info = malloc(sizeof(nss_mtl_user_info_t));
			if (info == NULL) {
				nss_mtl_utils_log(LOG_ERR, "%s: cannot allocate buffer for user info: %m", __func__);
				return NULL;
			}
			info->uid = entry->pw_uid;
			info->gid = entry->pw_gid;
			info->gecos = strdup(entry->pw_gecos);
			info->homedir_root = nss_mtl_parent_dir(entry->pw_dir);
			info->shell = strdup(entry->pw_shell);

			break;
		}
	}

	if (info == NULL) {
		nss_mtl_utils_log(LOG_WARNING, "%s: user %s not found in %s file", __func__, name, NSS_MTL_PASSWD_FILE);
	}

	return info;
}

void nss_mtl_user_info_free(nss_mtl_user_info_t* info) {
	assert(info != NULL);

	free(info->gecos);
	free(info->homedir_root);
	free(info->shell);
	free(info);
}

long nss_mtl_today() {
	time_t t = time(NULL);

	/* convert to days */
	return t / (60 * 60 * 24);
}

enum nss_status _nss_mtl_getpwnam_r(const char* name, struct passwd* pw, char* buffer, size_t buflen, int* errnop) {
	nss_mtl_config_t* config = nss_mtl_config_parse(NULL);
	if (config == NULL) {
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}
	nss_mtl_utils_log_setup(config->log_level);

	nss_mtl_utils_log(LOG_DEBUG, "%s: querying %s", __func__, name);

	if (nss_mtl_user_ignored(config, name) || nss_mtl_exec_ignored(config, program_invocation_short_name)) {
		nss_mtl_utils_log(LOG_INFO, "%s: ignoring query for user %s from exec %s", __func__, name, program_invocation_short_name);
		nss_mtl_config_free(config);
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	nss_mtl_user_info_t* target_user = nss_mtl_user_info_read(config->target_user);
	if (target_user == NULL) {
		nss_mtl_config_free(config);
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	pw->pw_name = nss_mtl_alloc_static(&buffer, &buflen, strlen(name) + 1);
	if (pw->pw_name == NULL) {
		goto bufsize_err;
	} else {
		strcpy(pw->pw_name, name);
	}

	pw->pw_passwd = nss_mtl_alloc_static(&buffer, &buflen, sizeof(char) * 2);
	if (pw->pw_passwd == NULL) {
		goto bufsize_err;
	} else {
		strcpy(pw->pw_passwd, "x");
	}

	pw->pw_uid = target_user->uid;
	pw->pw_gid = target_user->gid;

	pw->pw_gecos = nss_mtl_alloc_static(&buffer, &buflen, strlen(target_user->gecos) + 1);
	if (pw->pw_gecos == NULL) {
		goto bufsize_err;
	} else {
		strcpy(pw->pw_gecos, target_user->gecos);
	}

	const size_t homedir_size = strlen(target_user->homedir_root) + strlen(name) + 2;
	pw->pw_dir = nss_mtl_alloc_static(&buffer, &buflen, homedir_size);
	if (pw->pw_dir == NULL) {
		goto bufsize_err;
	} else {
		snprintf(pw->pw_dir, homedir_size, "%s/%s", target_user->homedir_root, name);
	}

	pw->pw_shell = nss_mtl_alloc_static(&buffer, &buflen, strlen(target_user->shell) + 1);
	if (pw->pw_shell == NULL) {
		goto bufsize_err;
	} else {
		strcpy(pw->pw_shell, target_user->shell);
	}

	/* store last used argument to properly assign groups for non-local users during login procedure */
	nss_mtl_utils_log(LOG_DEBUG, "%s: storing session user %s", __func__, name);
	strncpy(nss_mtl_current_user, name, LOGIN_NAME_MAX);

	nss_mtl_config_free(config);
	nss_mtl_user_info_free(target_user);
	return NSS_STATUS_SUCCESS;

	bufsize_err:
	*errnop = ERANGE;
	nss_mtl_config_free(config);
	nss_mtl_user_info_free(target_user);
	return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_mtl_getspnam_r(const char* name, struct spwd* spw, char* buffer, size_t buflen, int* errnop) {
	nss_mtl_config_t* config = nss_mtl_config_parse(NULL);
	if (config == NULL) {
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}
	nss_mtl_utils_log_setup(config->log_level);

	nss_mtl_utils_log(LOG_DEBUG, "%s: querying %s", __func__, name);

	if (nss_mtl_user_ignored(config, name) || nss_mtl_exec_ignored(config, program_invocation_short_name)) {
		nss_mtl_utils_log(LOG_INFO, "%s: ignoring query for user %s from %s", __func__, name, program_invocation_short_name);
		nss_mtl_config_free(config);
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	spw->sp_namp = nss_mtl_alloc_static(&buffer, &buflen, strlen(name) + 1);
	if (spw->sp_namp == NULL) {
		goto bufsize_err;
	}
	strcpy(spw->sp_namp, name);

	spw->sp_pwdp = nss_mtl_alloc_static(&buffer, &buflen, sizeof(char) * 2);
	if (spw->sp_pwdp == NULL) {
		goto bufsize_err;
	}
	strcpy(spw->sp_pwdp, "*");

	long today = nss_mtl_today();

	spw->sp_lstchg = today;
	spw->sp_min = 0;
	spw->sp_max = LONG_MAX;
	spw->sp_warn = LONG_MAX;
	spw->sp_inact = LONG_MAX;
	spw->sp_expire = today + 1;

	return NSS_STATUS_SUCCESS;

	bufsize_err:
	*errnop = ERANGE;
	nss_mtl_config_free(config);
	return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_mtl_setgrent(void) {
	if (nss_mtl_config == NULL) {
		nss_mtl_config = nss_mtl_config_parse(NULL);
		if (nss_mtl_config == NULL) {
			return NSS_STATUS_UNAVAIL;
		}
		nss_mtl_utils_log_setup(nss_mtl_config->log_level);
	}
	if (nss_mtl_active_users == NULL) {
		nss_mtl_active_users = nss_mtl_utils_users_get();
		if (nss_mtl_active_users == NULL) {
			nss_mtl_utils_log(LOG_ERR, "%s: failed to acquire active users list", __func__);
			return NSS_STATUS_UNAVAIL;
		}
	}

	if (nss_mtl_group == NULL) {
		nss_mtl_group = fopen(NSS_MTL_GROUP_FILE, "r");
		if (nss_mtl_group == NULL) {
			nss_mtl_utils_log(LOG_ERR, "%s: failed to open %s for reading", __func__, NSS_MTL_GROUP_FILE);
			nss_mtl_utils_list_free(nss_mtl_active_users);
			nss_mtl_active_users = NULL;
			return NSS_STATUS_UNAVAIL;
		}
		if (fcntl(fileno(nss_mtl_group), F_SETFD, FD_CLOEXEC) == -1) {
			nss_mtl_utils_log(LOG_WARNING, "%s: failed to modify file descriptor: %m", __func__);
			/* this is not critical, so we can continue */
		}
	} else {
		rewind(nss_mtl_group);
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mtl_endgrent(void) {
	if (nss_mtl_group != NULL) {
		fclose(nss_mtl_group);
		nss_mtl_group = NULL;
	}

	if (nss_mtl_active_users != NULL) {
		nss_mtl_utils_list_free(nss_mtl_active_users);
		nss_mtl_active_users = NULL;
	}

	if (nss_mtl_config != NULL) {
		nss_mtl_config_free(nss_mtl_config);
		nss_mtl_config = NULL;
	}

	return NSS_STATUS_SUCCESS;
}

bool nss_mtl_group_adapt(nss_mtl_config_t* config, nss_mtl_utils_list_t* active_users, struct group* dst, const struct group* src, char* buffer, size_t buflen) {
	assert(config != NULL);
	assert(active_users != NULL);
	assert(dst != NULL);
	assert(src != NULL);
	assert(buffer != NULL);

	dst->gr_name = nss_mtl_alloc_static(&buffer, &buflen, strlen(src->gr_name) + 1);
	if (dst->gr_name == NULL) {
		return false;
	} else {
		strcpy(dst->gr_name, src->gr_name);
	}

	dst->gr_passwd = nss_mtl_alloc_static(&buffer, &buflen, strlen(src->gr_passwd) + 1);
	if (dst->gr_passwd == NULL) {
		return false;
	} else {
		strcpy(dst->gr_passwd, src->gr_passwd);
	}

	dst->gr_gid = src->gr_gid;

	size_t msize = 0;
	bool has_target_user = false;
	while (src->gr_mem[msize] != NULL) {
		if (strcmp(src->gr_mem[msize], config->target_user) == 0) {
			has_target_user = true;
		}
		++msize;
	}

	bool add_current_user = has_target_user && (strlen(nss_mtl_current_user) > 0);
	const size_t target_msize = msize + (has_target_user ? active_users->filled : 0) + (add_current_user ? 1 : 0) + 1;
	dst->gr_mem = (char**)nss_mtl_alloc_static(&buffer, &buflen, target_msize * sizeof(char*));
	if (dst->gr_mem == NULL) {
		return false;
	}
	memset(dst->gr_mem, 0, target_msize * sizeof(char*));

	int idx = 0;
	for (size_t i = 0; i < msize; ++i) {
		if (strcmp(src->gr_mem[i], config->target_user) == 0) {
			nss_mtl_utils_log(LOG_DEBUG, "%s: found %s as group %s member, extending with active users", __func__, config->target_user, src->gr_name);
			for (size_t k = 0; k < active_users->filled; ++k) {
				dst->gr_mem[idx] = nss_mtl_alloc_static(&buffer, &buflen, strlen(active_users->items[k]) + 1);
				if (dst->gr_mem[idx] == NULL) {
					return false;
				} else {
					strcpy(dst->gr_mem[idx++], active_users->items[k]);
				}
			}
			if (add_current_user) {
				dst->gr_mem[idx] = nss_mtl_alloc_static(&buffer, &buflen, strlen(nss_mtl_current_user) + 1);
				if (dst->gr_mem[idx] == NULL) {
					return false;
				} else {
					strcpy(dst->gr_mem[idx++], nss_mtl_current_user);
				}
			}
		}
		if (add_current_user && (strcmp(src->gr_mem[i], nss_mtl_current_user) == 0)) {
			/* avoid duplicates */
			continue;
		}
		dst->gr_mem[idx] = nss_mtl_alloc_static(&buffer, &buflen, strlen(src->gr_mem[i]) + 1);
		if (dst->gr_mem[idx] == NULL) {
			return false;
		} else {
			strcpy(dst->gr_mem[idx++], src->gr_mem[i]);
		}
	}

	return true;
}

enum nss_status _nss_mtl_getgrent_r(struct group* grp, char* buffer, size_t buflen, int* errnop) {
	if (nss_mtl_group == NULL || nss_mtl_active_users == NULL || nss_mtl_config == NULL) {
		nss_mtl_utils_log(LOG_WARNING, "%s: group database not initialized", __func__);
		enum nss_status status = _nss_mtl_setgrent();
		if (status != NSS_STATUS_SUCCESS) {
			return status;
		}
	}

	const struct group* entry = fgetgrent(nss_mtl_group);
	if (entry == NULL) {
		return NSS_STATUS_NOTFOUND;
	} else if (! nss_mtl_group_adapt(nss_mtl_config, nss_mtl_active_users, grp, entry, buffer, buflen)) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		return NSS_STATUS_SUCCESS;
	}
}

enum nss_status _nss_mtl_getgrnam_r(const char* name, struct group* grp, char* buffer, size_t buflen, int* errnop) {
	nss_mtl_config_t* config = nss_mtl_config_parse(NULL);
	if (config == NULL) {
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}
	nss_mtl_utils_log_setup(config->log_level);

	nss_mtl_utils_list_t* active_users = nss_mtl_utils_users_get();
	if (active_users == NULL) {
		nss_mtl_config_free(config);
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	FILE* f = fopen(NSS_MTL_GROUP_FILE, "r");
	if (f == NULL) {
		nss_mtl_utils_log(LOG_ERR, "%s: failed to open %s for reading: %m", __func__, NSS_MTL_GROUP_FILE);
		nss_mtl_config_free(config);
		nss_mtl_utils_list_free(active_users);
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	enum nss_status status = NSS_STATUS_NOTFOUND;

	const struct group* entry = NULL;
	while ((entry = fgetgrent(f)) != NULL) {
		if (strcmp(entry->gr_name, name) == 0) {
			if (! nss_mtl_group_adapt(config, active_users, grp, entry, buffer, buflen)) {
				*errnop = ERANGE;
				status = NSS_STATUS_TRYAGAIN;
			} else {
				status = NSS_STATUS_SUCCESS;
			}
			break;
		}
	}

	fclose(f);
	nss_mtl_config_free(config);
	nss_mtl_utils_list_free(active_users);

	return status;
}

enum nss_status _nss_mtl_getgrgid_r(gid_t gid, struct group* grp, char* buffer, size_t buflen, int* errnop) {
	nss_mtl_config_t* config = nss_mtl_config_parse(NULL);
	if (config == NULL) {
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}
	nss_mtl_utils_log_setup(config->log_level);

	nss_mtl_utils_list_t* active_users = nss_mtl_utils_users_get();
	if (active_users == NULL) {
		nss_mtl_config_free(config);
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	FILE* f = fopen(NSS_MTL_GROUP_FILE, "r");
	if (f == NULL) {
		nss_mtl_utils_log(LOG_ERR, "%s: failed to open %s for reading: %m", __func__, NSS_MTL_GROUP_FILE);
		nss_mtl_config_free(config);
		nss_mtl_utils_list_free(active_users);
		*errnop = ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	enum nss_status status = NSS_STATUS_NOTFOUND;

	const struct group* entry = NULL;
	while ((entry = fgetgrent(f)) != NULL) {
		if (entry->gr_gid == gid) {
			if (! nss_mtl_group_adapt(config, active_users, grp, entry, buffer, buflen)) {
				*errnop = ERANGE;
				status = NSS_STATUS_TRYAGAIN;
			} else {
				status = NSS_STATUS_SUCCESS;
			}
			break;
		}
	}

	fclose(f);
	nss_mtl_config_free(config);
	nss_mtl_utils_list_free(active_users);

	return status;
}