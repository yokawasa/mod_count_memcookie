/*
 * mod_count_memcookie.c - Memcached Counter of User's Page View Based on User Cookie
 *
 * Copyright (C) 2009 Yoichi Kawasaki All rights reserved.
 * www.yk55.com
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
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"      // ap_log_rerror
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_base64.h" // apr_base64_encode
#include "memcache.h"

#define MODTAG "CountMemCookie: "
#define MEM_MIN_COUNT  (1)
#define MEM_TABLE_SIZE_NO_LIMIT  (0)

/* apache module name */
module AP_MODULE_DECLARE_DATA count_memcookie_module;


static apr_array_header_t *mem_addr_arr;

typedef struct {
    int enabled;
    char *cookie_name;
    int mem_expiry;
    char* mem_addr;
    int mem_table_size;
    int set_header;
} count_memcookie_config;

void set_default(count_memcookie_config *conf)
{
    if(!conf){
        return;
    }
    conf->enabled = 0;
    conf->cookie_name = NULL;
    conf->mem_expiry = 0;
    conf->mem_addr = NULL;
    conf->mem_table_size = MEM_TABLE_SIZE_NO_LIMIT;
    conf->set_header = 0;
}

static void* count_memcookie_create_dir_config(apr_pool_t *p, char *d)
{
    count_memcookie_config* conf = apr_pcalloc(p, sizeof(count_memcookie_config));
    set_default(conf);
    return conf;
}

static void* count_memcookie_merge_dir_config(apr_pool_t *p,
                                void *parent_conf, void *new_conf)
{
    count_memcookie_config *pc = (count_memcookie_config *)parent_conf;
    count_memcookie_config *nc = (count_memcookie_config *)new_conf;

    count_memcookie_config *conf
            = (count_memcookie_config *) apr_pcalloc(p, sizeof(count_memcookie_config));
    conf->enabled = (nc->enabled?nc->enabled:pc->enabled);
    conf->cookie_name  = (nc->cookie_name?nc->cookie_name:pc->cookie_name);
    conf->mem_expiry   = (nc->mem_expiry?nc->mem_expiry:pc->mem_expiry);
    conf->mem_addr   = (nc->mem_addr?nc->mem_addr:pc->mem_addr);
    conf->mem_table_size   = (nc->mem_table_size?nc->mem_table_size:pc->mem_table_size);
    conf->set_header   = (nc->set_header?nc->set_header:pc->set_header);

    return conf;
}

static char* find_cookie(request_rec *r, const char* cookie_name)
{

    const char* cookies;
    char *cookie = NULL;

    /* todo: protect against xxxCookieNamexxx, regex? */
    /* todo: make case insensitive? */
    /* Get the cookie (code from mod_log_config). */
    if ((cookies = apr_table_get(r->headers_in, "Cookie"))) {
        char *start_cookie, *end_cookie;
        if ((start_cookie = ap_strstr_c(cookies, cookie_name))) {
            start_cookie += strlen(cookie_name) + 1;
            cookie = apr_pstrdup(r->pool, start_cookie);
            /* kill everything in cookie after ';' */
            end_cookie = strchr(cookie, ';');
            if (end_cookie) {
                *end_cookie = '\0';
            }
        }
    }
    if (!cookie) {
        return NULL;
    }
    return apr_pstrdup(r->pool,cookie);
}

static int set_memcookie_counter(request_rec *r, const char* key,
                    const char* mem_addr, int mem_expiry, int mem_table_size )
{
    int count = MEM_MIN_COUNT;
    char* count_str = NULL;
    size_t cur_table_size = 0;
    char* cur_table_size_str = NULL;
    int ret;
    struct memcache *mem =NULL;
    struct memcache_req *req = NULL;
    struct memcache_res *res1= NULL;
    struct memcache_res *res2= NULL;

    mem = mc_new();
    if (!mem) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, MODTAG "memcache init failure");
        return count;
    }

    /*
    * split mem_addr string into each server addr
    */
    int i=0;
    char *next, *last;
    char* mem_addr_tmp = (char*)apr_pstrdup(r->pool, mem_addr);
    next =  (char*)apr_strtok( mem_addr_tmp, ",", &last);
    while (next) {
        apr_collapse_spaces (next, next);
        ret = mc_server_add4( mem, next);
        if (ret!=0 ) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "mc_server_add4 failiure: svr %s err=%d",next,ret);
            mc_free(mem);
            return count;
        }
        i++;
        next = (char*)apr_strtok(NULL, ",", &last);
    }
    if ( i < 1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, MODTAG "wrong mem_addr failure");
        mc_free(mem);
        return count;
    }

    req = mc_req_new();
    /*
    * set request keys and get results
    */
    if (mem_table_size != MEM_TABLE_SIZE_NO_LIMIT ) {
        res1 = mc_req_add( req, "tsize", strlen("tsize"));
    }
    res2 = mc_req_add( req, (char*)key, strlen(key));
    mc_get( mem, req );

    /*
    * get the user's PV count from memcached
    */
    if( !res2->val ) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, MODTAG "no value in memcached with key:%s", key);

        if (mem_table_size != MEM_TABLE_SIZE_NO_LIMIT ) {

            if( res1->val ) {
                cur_table_size = atoi( (char*)res1->val );
            }
            if (cur_table_size >=  mem_table_size) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                            MODTAG "counter table size reached max!! "
                            "please check out the value of CountMemCookieMemcachedTableSize ");
                mc_req_free( req );
                mc_free(mem);
                return count;
            }
            /*
            * save the incremented table size to memcached
            */
            cur_table_size++;
            cur_table_size_str=apr_psprintf(r->pool, "%d", cur_table_size);
            ret = mc_set(
                    mem,
                    "tsize", strlen("tsize"),
                    cur_table_size_str, strlen(cur_table_size_str),
                    0,
                    0);

            if( ret != 0 ){
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                                MODTAG "memcache set failure key:tsize");
                // even though cur_table_size was not saved to memcached, table size limit
                // is not so important enough to stop the rest of operations. So let it go!
            }
        }

        /*
        * save the initial count to memcached
        */
        count_str=apr_psprintf(r->pool, "%d", count);
        ret = mc_set(
                mem,
                (char*)key, strlen(key),
                count_str, strlen(count_str),
                mem_expiry,
                0);

        if( ret != 0 ){
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                            MODTAG "memcache set failure key:%s", key);
        }
        mc_req_free( req );
        mc_free(mem);
        return count;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, MODTAG "USER COUNTER=%s", (char*)res2->val );
    count = atoi( (char*)res2->val );
    mc_req_free( req );

    /*
    * save the incremented count to memcached
    */
    count++;
    count_str=apr_psprintf(r->pool, "%d", count);
    ret = mc_set(
             mem,
             (char*)key, strlen(key),
             count_str, strlen(count_str),
             mem_expiry,
             0);

    if( ret != 0 ){
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                         MODTAG "memcache set failure key:%s", key);
    }

    mc_free(mem);
    return count;
}

static int count_memcookie_access_checker(request_rec *r)
{
    count_memcookie_config *conf = ap_get_module_config(r->per_dir_config, &count_memcookie_module);

    char* cookie;
    char* b64cookiebuf;
    int b64len;
    int curcount;
    char* curcount_str;

    if (!conf || !conf->enabled) {
        return DECLINED;
    }
    /*
    *  validation check on given info
    */
    if (!conf->cookie_name ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "CountMemCookieName not specified!");
        return DECLINED;
    }
    if (!conf->mem_addr ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "CountMemCookieMemcachedAddrPort not specified!");
        return DECLINED;
    }
    if (conf->mem_expiry < 1 ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "CountMemCookieMemcachedObjectExpiry is invalid or  not specified!");
        return DECLINED;
    }
    if (conf->mem_table_size < 0 ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "CountMemCookieMemcachedTableSize is invalid!");
        return DECLINED;
    }

    cookie = find_cookie(r, conf->cookie_name);

    if (!cookie || strlen(cookie) < 1 ) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, MODTAG "Cookie not found!");
        return DECLINED;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, MODTAG "FOUND COOKIE %s", cookie);

    /*
    * encode cookie in base64 format
    */
    b64len = apr_base64_encode_len( strlen(cookie) );
    b64cookiebuf = (char *) apr_palloc( r->pool, b64len + 1 );
    if(!b64cookiebuf){
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, MODTAG "memory alloc failed!");
       return DECLINED;
    }
    apr_base64_encode(b64cookiebuf,cookie,strlen(cookie));
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, MODTAG "BASE64 COOKIE %s",  (char*)b64cookiebuf);

    curcount = set_memcookie_counter(r,b64cookiebuf,
            conf->mem_addr, conf->mem_expiry, conf->mem_table_size );

    curcount_str = apr_psprintf(r->pool, "%d", curcount );

    /* set cur count in subprocess_env table for script language */
    apr_table_setn(r->subprocess_env, "count_memcookie", curcount_str);
    /* set cur count in http header */
    if (conf->set_header) {
        apr_table_set(r->headers_in, "count_memcookie", curcount_str);
    }
    return OK;
}

static void count_memcookie_register_hooks(apr_pool_t *p)
{
    ap_hook_access_checker(count_memcookie_access_checker, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec count_memcookie_cmds[] =
{
    AP_INIT_FLAG("CountMemCookieEnabled", ap_set_flag_slot,
        (void *)APR_OFFSETOF(count_memcookie_config, enabled),
        OR_FILEINFO, "set \"On\" to enable count_memcookie, \"Off\" to disable"),
    AP_INIT_TAKE1("CountMemCookieName",ap_set_string_slot,
        (void *)APR_OFFSETOF(count_memcookie_config, cookie_name),
        OR_FILEINFO, "Name of cookie to lookup"),
    AP_INIT_TAKE1("CountMemCookieMemcachedAddrPort", ap_set_string_slot,
        (void *)APR_OFFSETOF(count_memcookie_config, mem_addr),
        OR_FILEINFO, "Liste of the memcached address( ip or host adresse(s) and port ':' separated). The addresses are ',' comma separated"),
    AP_INIT_TAKE1("CountMemCookieMemcachedObjectExpiry", ap_set_int_slot,
        (void *)APR_OFFSETOF(count_memcookie_config, mem_expiry),
        OR_FILEINFO, "expiry time of session object in memcached in seconds"),
    AP_INIT_TAKE1("CountMemCookieMemcachedTableSize",ap_set_int_slot,
        (void *)APR_OFFSETOF(count_memcookie_config, mem_table_size),
        OR_FILEINFO, "Max number of element in session table of memcached. 0 by default, no limit"),
    AP_INIT_FLAG("CountMemCookieSetHTTPHeader",ap_set_flag_slot,
        (void *)APR_OFFSETOF(count_memcookie_config, set_header),
        OR_FILEINFO, "Set to \"On\" to set count information to http header. \"Off\" by default"),
    {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA count_memcookie_module = {
    STANDARD20_MODULE_STUFF,
    count_memcookie_create_dir_config,        /* create per-dir    config structures */
    //count_memcookie_merge_dir_config,       /* merge  per-dir    config structures */
    NULL,                                     /* merge  per-dir    config structures */
    NULL,                                     /* create per-server config structures */
    NULL,                                     /* merge  per-server config structures */
    count_memcookie_cmds,                     /* table of config file commands       */
    count_memcookie_register_hooks            /* register hooks                      */
};

/*
 * vim:ts=4 et
 */
