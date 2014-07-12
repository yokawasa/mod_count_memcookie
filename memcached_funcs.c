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

#include "httpd.h"
#include "http_log.h"
#include <inttypes.h>        //for PRIu64 definition
#include <libmemcached/memcached.h>
#include "commons.h"
#include "memcached_funcs.h"
#include "apr_strings.h"     //for apr_pstrdup, apr_psprintf definition


static memcached_st *memc = NULL;
static memcached_server_st *servers = NULL;

static apr_status_t
_cleanup_register_cmemcookie_func(void *dummy)
{
    if(servers){
        memcached_server_list_free(servers);
        servers = NULL;
    }
    if(memc){
        memcached_free(memc);
        memc = NULL;
    }
    return APR_SUCCESS;
}

int _init_cmemcookie_func(request_rec *r, apr_array_header_t *memc_addrs)
{
    int i;
    memc_addr_cmemcookie_entry *memc_addr, *ma;
    memcached_return rc;
    memc = memcached_create(NULL);
    int binary_available = 0;
    if (!memc) {
        CMLOG_ERROR( r, MODTAG "memcached_create failure!");
        return -1;
    }
    if(memc_addrs) {
        ma = (memc_addr_cmemcookie_entry *)memc_addrs->elts;
        if (memc_addrs->nelts < 1) {
            CMLOG_ERROR( r, MODTAG "no memcached server to push!");
            return -1;
        }
        binary_available = 1;
        for ( i =0; i <memc_addrs->nelts; i++) {
            memc_addr =  &ma[i];
            if (i==0) {
                servers = memcached_server_list_append_with_weight(NULL, memc_addr->hostname, memc_addr->port, 0, &rc);
            } else {
                servers = memcached_server_list_append_with_weight(servers, memc_addr->hostname, memc_addr->port, 0, &rc);
            }
            if (rc != MEMCACHED_SUCCESS) {
                CMLOG_ERROR(r, MODTAG "memcached_server_list_append_with_weight failure: server=%s:%d rc=%d",
                        memc_addr->hostname, memc_addr->port, rc);
                return -1;
            }
        }
        rc = memcached_server_push(memc, servers);
        if (rc != MEMCACHED_SUCCESS) {
            CMLOG_ERROR(r, MODTAG "memcached_server_push failure: rc=%d", rc);
            return -1;
        }

        //================================================================================
        // minimun version of  memcached for incr command with libmemcached
        //================================================================================
        //
        // there is 2 pre-requisite for incr command to use.
        //  1. libmemcached support incr command execution only in using binary protocol
        //  2. binary protocol is available with memcached-1.4.0 or up
        //     actually incr/decr commands are available with memcached > 1.2.6
        //  taking those 2 pre-requisites into consideration, for incr command to be used
        //  with libmemcached, memcached version has to be 1.4.0 or up.
        //
        memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NO_BLOCK, 0);
        rc = memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
        if (rc != MEMCACHED_SUCCESS) {
            CMLOG_ERROR(r, MODTAG "memcached_behavior_set failed to enable binary protocol: rc=%d", rc);
            return -1;
        }
    }
    apr_pool_cleanup_register(r->pool, NULL, _cleanup_register_cmemcookie_func, _cleanup_register_cmemcookie_func);
    return 0;
}

int memcached_init_cmemcookie_func(request_rec *r, apr_array_header_t *memc_addrs)
{
    if (!memc) {
        return _init_cmemcookie_func(r, memc_addrs);
    }
    return 0;
}

int memcached_get_cmemcookie_func(request_rec *r, const char *key, char **val)
{
    memcached_return rc;
    char *received;
    size_t length;
    uint32_t flags;
    if (!r || !key) {
        return -1;
    }
    received = memcached_get(memc, key, strlen(key),
                             &length, &flags, &rc);
    if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND ) {
        CMLOG_ERROR(r, MODTAG "memcached_get failure: key=%s rc=%d msg=%s",
                                    key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    if (received != NULL) {
        *val = (char*)apr_pstrdup(r->pool, received);
    }
    return 0;
}

int memcached_set_cmemcookie_func(request_rec *r, const char *key, const char *val, time_t expire)
{
    memcached_return rc;
    if (!r || !key || !val) {
        return -1;
    }
    rc = memcached_set(memc,
                       key, strlen(key),
                       val, strlen(val),
                       expire, (uint32_t)0);

    if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_BUFFERED){
        CMLOG_ERROR(r, MODTAG "memcached_set failure: key=%s rc=%d msg=%s",
                                    key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    return 0;
}

int memcached_incr_cmemcookie_func(request_rec *r, char *key, time_t expire, uint32_t *new_num )
{
// this increment interface is available only with binary protocol
// as far as i've checked, unitl the version 0.34 it is the case.
    memcached_return rc;
    uint64_t _new_num;
    char *tmp;
    if (!r || !key) {
        return -1;
    }
    rc= memcached_increment_with_initial(memc, key, strlen(key),
                                         1, 1, expire, &_new_num);
    if (rc != MEMCACHED_SUCCESS) {
        CMLOG_ERROR(r, MODTAG "memcached_increment_with_initial failure: key=%s rc=%d msg=%s",
                                 key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    *new_num = (uint32_t)_new_num;
    return 0;
}

