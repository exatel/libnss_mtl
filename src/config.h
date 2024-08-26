/*
 * config.h
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

#ifndef NSS_MTL_CONFIG_H
#define NSS_MTL_CONFIG_H

#include <sys/types.h>

#include "utils.h"

typedef struct {
	int log_level;
	char* target_user;
	nss_mtl_utils_list_t* ignored_users;
} nss_mtl_config_t;

nss_mtl_config_t* nss_mtl_config_parse(const char* path);
void nss_mtl_config_free(nss_mtl_config_t* config);

#endif /* NSS_MTL_CONFIG_H */