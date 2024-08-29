/*
 * mtl.h
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

#ifndef NSS_MTL_H
#define NSS_MTL_H

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>

#ifdef __cplusplus
extern "C" {
#endif

enum nss_status _nss_mtl_getpwnam_r(const char* name, struct passwd* pw, char* buffer, size_t buflen, int* errnop);

enum nss_status _nss_mtl_getspnam_r(const char* name, struct spwd* spw, char* buffer, size_t buflen, int* errnop);

enum nss_status _nss_mtl_setgrent(void);
enum nss_status _nss_mtl_endgrent(void);
enum nss_status _nss_mtl_getgrent_r(struct group* grp, char* buffer, size_t buflen, int* errnop);
enum nss_status _nss_mtl_getgrnam_r(const char* name, struct group* grp, char* buffer, size_t buflen, int* errnop);
enum nss_status _nss_mtl_getgrgid_r(gid_t gid, struct group* grp, char* buffer, size_t buflen, int* errnop);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NSS_MTL_H */