/*
 * Copyright (C) 2009 Yoichi Kawasaki All rights reserved.
 * yk55.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __MEMCACHED_CMEMCOOKIE_FUNCS_H__
#define __MEMCACHED_CMEMCOOKIE_FUNCS_H__

#include "httpd.h"
#include "apr_tables.h"

#define MEMCACHED_FUNCS_DEFAULT_EXPIRE_TIME DEFAULT_EXPIRE_TIME

typedef struct {
    char *hostname;
    unsigned int port;
} memc_addr_cmemcookie_entry;

int memcached_init_cmemcookie_func(request_rec *r, apr_array_header_t *memc_addrs);
int memcached_get_cmemcookie_func(request_rec *r, const char *key, char **val);
int memcached_set_cmemcookie_func(request_rec *r, const char *key, const char *val, time_t expire);
int memcached_incr_cmemcookie_func(request_rec *r, char *key, time_t expire, uint32_t *new_num );

#endif //__MEMCACHED_CMEMCOOKIE_FUNCS_H__
