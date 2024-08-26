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

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>


#include "config.h"
#include "utils.h"

#ifndef NSS_MTL_PASSWD_FILE
#define NSS_MTL_PASSWD_FILE "/etc/passwd"
#endif

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
static char* nss_mtl_parent_dir(const char* path);
static nss_mtl_user_info_t* nss_mtl_user_info_read(const char* name);
static void nss_mtl_user_info_free(nss_mtl_user_info_t* info);
static enum nss_status nss_mtl_group_adapt(struct group* dst, const struct group* src, char* buffer, size_t buflen, int* errnop);

static FILE* nss_mtl_group = NULL;
static nss_mtl_config_t* nss_mtl_config = NULL;
static nss_mtl_utils_list_t* nss_mtl_active_users = NULL;
static nss_mtl_user_info_t* nss_mtl_target_user_info = NULL;

/* implementation */

char* nss_mtl_alloc_static(char** buffer, size_t* buflen, size_t size) {
	if (buffer == NULL || buflen == NULL || *buflen < size) {
		syslog(LOG_WARNING, "%s: cannot allocate buffer of size %ld", __func__, size);
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
	return bsearch(name, ignored->items, ignored->filled, sizeof(char*), nss_mtl_utils_str_cmp) != NULL;
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
		syslog(LOG_ERR, "%s: failed to open %s for reading: %m", __func__, NSS_MTL_PASSWD_FILE);
		return NULL;
	}

	nss_mtl_user_info_t* info = NULL;
	struct passwd* entry = NULL;
	while ((entry = fgetpwent(f)) != NULL) {
		if (entry->pw_name == NULL) {
			syslog(LOG_WARNING, "%s: found empty username in passwd file", __func__);
			continue;
		}
		if (strcmp(entry->pw_name, name) == 0) {
			info = malloc(sizeof(nss_mtl_user_info_t));
			if (info == NULL) {
				syslog(LOG_ERR, "%s: cannot allocate buffer for user info: %m", __func__);
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
		syslog(LOG_ERR, "%s: target user %s not found in %s file", __func__, name, NSS_MTL_PASSWD_FILE);
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

enum nss_status _nss_mtl_setpwent(void) {
	if (nss_mtl_config == NULL) {
		nss_mtl_config = nss_mtl_config_parse(NULL);
		if (nss_mtl_config == NULL) {
			return NSS_STATUS_UNAVAIL;
		}
	}

	if (nss_mtl_target_user_info == NULL) {
		nss_mtl_target_user_info = nss_mtl_user_info_read(nss_mtl_config->target_user);
		if (nss_mtl_target_user_info == NULL) {
			nss_mtl_config_free(nss_mtl_config);
			nss_mtl_config = NULL;
			return NSS_STATUS_UNAVAIL;
		}
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mtl_endpwent(void) {
	if (nss_mtl_target_user_info != NULL) {
		nss_mtl_user_info_free(nss_mtl_target_user_info);
		nss_mtl_target_user_info = NULL;
	}

	if (nss_mtl_config != NULL) {
		nss_mtl_config_free(nss_mtl_config);
		nss_mtl_config = NULL;
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mtl_getpwnam_r(const char* name, struct passwd* pw, char* buffer, size_t buflen, int* errnop) {
	if (nss_mtl_config == NULL || nss_mtl_target_user_info == NULL) {
		syslog(LOG_ERR, "%s: passwd database not initialized", __func__);
		return NSS_STATUS_UNAVAIL;
	}

	if (nss_mtl_user_ignored(nss_mtl_config, name)) {
		syslog(LOG_DEBUG, "%s: ignoring user %s", __func__, name);
		return NSS_STATUS_NOTFOUND;
	}

	pw->pw_name = nss_mtl_alloc_static(&buffer, &buflen, strlen(name) + 1);
	if (pw->pw_name == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		strcpy(pw->pw_name, name);
	}

	pw->pw_passwd = nss_mtl_alloc_static(&buffer, &buflen, sizeof(char) * 2);
	if (pw->pw_passwd == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		strcpy(pw->pw_passwd, "x");
	}

	pw->pw_uid = nss_mtl_target_user_info->uid;
	pw->pw_gid = nss_mtl_target_user_info->gid;

	pw->pw_gecos = nss_mtl_alloc_static(&buffer, &buflen, strlen(nss_mtl_target_user_info->gecos) + 1);
	if (pw->pw_gecos == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		strcpy(pw->pw_gecos, nss_mtl_target_user_info->gecos);
	}

	const size_t homedir_size = strlen(nss_mtl_target_user_info->homedir_root) + strlen(name) + 2;
	pw->pw_dir = nss_mtl_alloc_static(&buffer, &buflen, homedir_size);
	if (pw->pw_dir == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		snprintf(pw->pw_dir, homedir_size, "%s/%s", nss_mtl_target_user_info->homedir_root, name);
	}

	pw->pw_shell = nss_mtl_alloc_static(&buffer, &buflen, strlen(nss_mtl_target_user_info->shell) + 1);
	if (pw->pw_shell == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		strcpy(pw->pw_shell, nss_mtl_target_user_info->shell);
	}

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mtl_getspnam_r(const char* name, struct spwd* spw, char* buffer, size_t buflen, int* errnop) {
	spw->sp_namp = nss_mtl_alloc_static(&buffer, &buflen, strlen(name) + 1);
	if (spw->sp_namp == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}
	strcpy(spw->sp_namp, name);

	spw->sp_pwdp = nss_mtl_alloc_static(&buffer, &buflen, sizeof(char) * 2);
	if (spw->sp_pwdp == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}
	strcpy(spw->sp_pwdp, "*");

	spw->sp_lstchg = 0;
	spw->sp_min = 0;
	spw->sp_max = LONG_MAX;
	spw->sp_warn = LONG_MAX;
	spw->sp_inact = 0;
	spw->sp_expire = LONG_MAX;

	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mtl_setgrent(void) {
	if (nss_mtl_config == NULL) {
		nss_mtl_config = nss_mtl_config_parse(NULL);
		if (nss_mtl_config == NULL) {
			return NSS_STATUS_UNAVAIL;
		}
	}
	if (nss_mtl_active_users == NULL) {
		nss_mtl_active_users = nss_mtl_utils_users_get();
		if (nss_mtl_active_users == NULL) {
			syslog(LOG_ERR, "%s: failed to acquire active users list", __func__);
			return NSS_STATUS_UNAVAIL;
		}
	}

	if (nss_mtl_group == NULL) {
		nss_mtl_group = fopen(NSS_MTL_GROUP_FILE, "r");
		if (nss_mtl_group == NULL) {
			syslog(LOG_ERR, "%s: failed to open %s for reading", __func__, NSS_MTL_GROUP_FILE);
			nss_mtl_utils_list_free(nss_mtl_active_users);
			nss_mtl_active_users = NULL;
			return NSS_STATUS_UNAVAIL;
		}
		if (fcntl(fileno(nss_mtl_group), F_SETFD, FD_CLOEXEC) == -1) {
			syslog(LOG_WARNING, "%s: failed to modify file descriptor: %m", __func__);
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

enum nss_status nss_mtl_group_adapt(struct group* dst, const struct group* src, char* buffer, size_t buflen, int* errnop) {
	assert(nss_mtl_config != NULL);
	assert(nss_mtl_active_users != NULL);

	dst->gr_name = nss_mtl_alloc_static(&buffer, &buflen, strlen(src->gr_name) + 1);
	if (dst->gr_name == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		strcpy(dst->gr_name, src->gr_name);
	}

	dst->gr_passwd = nss_mtl_alloc_static(&buffer, &buflen, strlen(src->gr_passwd) + 1);
	if (dst->gr_passwd == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	} else {
		strcpy(dst->gr_passwd, src->gr_passwd);
	}

	dst->gr_gid = src->gr_gid;

	size_t msize = 0;
	bool has_target_user = false;
	while (src->gr_mem[msize] != NULL) {
		if (strcmp(src->gr_mem[msize], nss_mtl_config->target_user) == 0) {
			has_target_user = true;
		}
		++msize;
	}

	const size_t target_msize = msize + (has_target_user ? nss_mtl_active_users->filled : 1);
	dst->gr_mem = (char**)nss_mtl_alloc_static(&buffer, &buflen, target_msize * sizeof(char*));
	if (dst->gr_mem == NULL) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}

	for (size_t i = 0, j = 0; i < msize; ++i) {
		if (strcmp(src->gr_mem[i], nss_mtl_config->target_user) == 0) {
			for (size_t k = 0; k < nss_mtl_active_users->filled; ++k) {
				dst->gr_mem[j] = nss_mtl_alloc_static(&buffer, &buflen, strlen(nss_mtl_active_users->items[k]) + 1);
				if (dst->gr_mem[j] == NULL) {
					*errnop = ERANGE;
					return NSS_STATUS_TRYAGAIN;
				} else {
					strcpy(dst->gr_mem[j++], nss_mtl_active_users->items[k]);
				}
			}
		} else {
			dst->gr_mem[j] = nss_mtl_alloc_static(&buffer, &buflen, strlen(src->gr_mem[i]) + 1);
			if (dst->gr_mem[j] == NULL) {
				*errnop = ERANGE;
				return NSS_STATUS_TRYAGAIN;
			} else {
				strcpy(dst->gr_mem[j++], src->gr_mem[i]);
			}
		}
	}


	return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_mtl_getgrent_r(struct group* grp, char* buffer, size_t buflen, int* errnop) {
	if (nss_mtl_group == NULL || nss_mtl_active_users == NULL || nss_mtl_config == NULL) {
		syslog(LOG_WARNING, "%s: group database not initialized", __func__);
		enum nss_status status = _nss_mtl_setgrent();
		if (status != NSS_STATUS_SUCCESS) {
			return status;
		}
	}

	const struct group* entry = fgetgrent(nss_mtl_group);
	return (entry != NULL) ? nss_mtl_group_adapt(grp, entry, buffer, buflen, errnop) : NSS_STATUS_NOTFOUND;
}

enum nss_status _nss_mtl_getgrnam_r(const char* name, struct group* grp, char* buffer, size_t buflen, int* errnop) {
	if (nss_mtl_active_users == NULL || nss_mtl_config == NULL) {
		syslog(LOG_ERR, "%s: group database not initialized", __func__);
		return NSS_STATUS_UNAVAIL;
	}

	FILE* f = fopen(NSS_MTL_GROUP_FILE, "r");
	if (f == NULL) {
		syslog(LOG_ERR, "%s: failed to open %s for reading: %m", __func__, NSS_MTL_GROUP_FILE);
		return NSS_STATUS_UNAVAIL;
	}

	enum nss_status status = NSS_STATUS_NOTFOUND;
	const struct group* entry = NULL;
	while ((entry = fgetgrent(f)) != NULL) {
		if (strcmp(entry->gr_name, name) == 0) {
			status = nss_mtl_group_adapt(grp, entry, buffer, buflen, errnop);
			break;
		}
	}

	fclose(f);

	return status;
}