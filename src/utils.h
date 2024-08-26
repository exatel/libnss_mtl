/*
 * utils.h
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

#ifndef NSS_MTL_UTILS_H
#define NSS_MTL_UTILS_H

#include <search.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	size_t size;
	size_t filled;
	char* items[];
} nss_mtl_utils_list_t;

void nss_mtl_utils_tree_size_calc(const void* node, VISIT which, void* closure);
void nss_mtl_utils_list_fill(const void* node, VISIT which, void* closure);

nss_mtl_utils_list_t* nss_mtl_utils_list_alloc(size_t nmemb);
void nss_mtl_utils_list_free(nss_mtl_utils_list_t* lst);

int nss_mtl_utils_str_cmp(const void* a, const void* b);
nss_mtl_utils_list_t* nss_mtl_utils_users_get(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NSS_MTL_UTILS_H */