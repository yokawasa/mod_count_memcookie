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
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"      // ap_log_rerror
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_base64.h" // apr_base64_encode
#include "commons.h"
#include "memcache.h"
#include "memcached_funcs.h"

#define MEMC_MIN_COUNT  (1)
#define INIT_MEMC_ADDR  (3)
#define MAX_MEMC_ADDR   (10)

/* apache module name */
module AP_MODULE_DECLARE_DATA count_memcookie_module;

typedef struct {
    int enabled;
    char *cookie_name;
    long memc_expiry;
    apr_array_header_t *memc_addrs;
    int set_header;
} count_memcookie_config;

static const char *set_enabled(cmd_parms *parms, void *mconfig, int arg)
{
    count_memcookie_config *conf = mconfig;
    if (!conf){
        return "CountMemCookieModule: Failed to retrieve configuration for mod_count_memcookie";
    }
    conf->enabled = arg;
    return NULL;
}

static const char *set_cookie_name(cmd_parms *parms, void *mconfig, const char *arg)
{
    count_memcookie_config *conf = mconfig;
    if (!conf){
        return "CountMemCookieModule: Failed to retrieve configuration for mod_count_memcookie";
    }
    conf->cookie_name = (char*)arg;
    return NULL;
}

static const char* parse_memc_addr(apr_pool_t *p, const char *val, memc_addr_cmemcookie_entry *memc_addr)
{
    char *next, *last;
    if ( !val||!memc_addr ) {
        return "parse_memc_addr: null arg";
    }
    next =  (char*)apr_strtok( (char*)val, ":", &last);
    if (!next||!last) {
        return "parse_memc_addr: invalid param";
    }
    memc_addr->hostname = next;
    memc_addr->port = atoi(last);
    return NULL;
}

static const char *set_memc_addr(cmd_parms *parms, void *mconfig, const char *arg)
{
    int i =0;
    const char *err;
    char *next, *last, *memc_addr_str;
    memc_addr_cmemcookie_entry *memc_addr;
    count_memcookie_config *conf = mconfig;
    if (!conf){
        return "CountMemCookieModule: Failed to retrieve configuration for mod_count_memcookie";
    }

    /*
    * split memc_addr string into each server addr
    */
    memc_addr_str = (char*)apr_pstrdup(parms->pool, (char*)arg);
    next =  (char*)apr_strtok( memc_addr_str, ",", &last);
    while (next) {
        apr_collapse_spaces (next, next);
        memc_addr = (memc_addr_cmemcookie_entry *)apr_array_push(conf->memc_addrs);
        if( (err = parse_memc_addr(parms->pool, next, memc_addr))!=NULL ) {
            return apr_psprintf(parms->pool, "CountMemCookieModule: %s", err);
        }
        i++;
        next = (char*)apr_strtok(NULL, ",", &last);
    }
    if ( i < 1) {
        return "CountMemCookieModule: Wrong Param: CountMemCookieMemcachedAddrPort";
    }
    return NULL;
}

static const char *set_memc_expiry(cmd_parms *parms, void *mconfig, const char *arg)
{
    long val;
    count_memcookie_config *conf = mconfig;
    if (!conf){
        return "CountMemCookieModule: Failed to retrieve configuration for mod_count_memcookie";
    }
    val = atol(arg);
    conf->memc_expiry = val;
    return NULL;
}

static const char *set_memc_table_size(cmd_parms *parms, void *mconfig, const char *arg)
{
    fprintf(stderr, MODTAG "[warning] CountMemCookieMemcachedTableSize directive has been deprecated since mod_count_memcookie-2.0.0.\n");
    return NULL;
}

static const char *set_setheader(cmd_parms *parms, void *mconfig, int arg)
{
    count_memcookie_config *conf = mconfig;
    if (!conf){
        return "CountMemCookieModule: Failed to retrieve configuration for mod_count_memcookie";
    }
    conf->set_header = arg;
    return NULL;
}

static void* count_memcookie_create_dir_config(apr_pool_t *p, char *d)
{
    count_memcookie_config* conf = apr_pcalloc(p, sizeof(count_memcookie_config));
    conf->enabled = 0;
    conf->cookie_name = NULL;
    conf->memc_expiry = 0;
    conf->memc_addrs = apr_array_make(p, INIT_MEMC_ADDR, sizeof(memc_addr_cmemcookie_entry));
    conf->set_header = 0;
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
                    apr_array_header_t *memc_addrs, long memc_expiry)
{
    int ret;
    uint32_t incred_count;

    if(!memc_addrs) {
        return MEMC_MIN_COUNT;
    }
    // init memcached
    ret = memcached_init_cmemcookie_func(r, memc_addrs);
    if (ret < 0) {
        return MEMC_MIN_COUNT;
    }
    // increment count and get incremented count
    ret = memcached_incr_cmemcookie_func(r, (char*)key, memc_expiry, &incred_count);
    if (ret < 0) {
        CMLOG_ERROR(r, MODTAG "increment count failure: USER KEY=%s", key );
        return MEMC_MIN_COUNT;
    }
    CMLOG_DEBUG(r, MODTAG "USER KEY(b64 cookie)=%s COUNTER=%d", key, incred_count);

    return incred_count;
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
        CMLOG_ERROR(r, MODTAG "CountMemCookieName not specified!");
        return DECLINED;
    }
    if (!conf->memc_addrs || conf->memc_addrs->nelts < 1) {
        CMLOG_ERROR(r, MODTAG "CountMemCookieMemcachedAddrPort not specified!");
        return DECLINED;
    }
    if (conf->memc_expiry < 1 ) {
        CMLOG_ERROR(r, MODTAG "CountMemCookieMemcachedObjectExpiry is invalid or  not specified!");
        return DECLINED;
    }

    cookie = find_cookie(r, conf->cookie_name);

    if (!cookie || strlen(cookie) < 1 ) {
        CMLOG_DEBUG(r, MODTAG "Cookie not found!");
        return DECLINED;
    }
    CMLOG_DEBUG(r, MODTAG "FOUND COOKIE %s", cookie);

    /*
    * encode cookie in base64 format
    */
    b64len = apr_base64_encode_len( strlen(cookie) );
    b64cookiebuf = (char *) apr_palloc( r->pool, b64len + 1 );
    if(!b64cookiebuf){
       CMLOG_ERROR(r, MODTAG "memory alloc failed!");
       return DECLINED;
    }
    apr_base64_encode(b64cookiebuf,cookie,strlen(cookie));

    curcount = set_memcookie_counter(r,b64cookiebuf,
                        conf->memc_addrs, conf->memc_expiry );

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
    AP_INIT_FLAG("CountMemCookieEnabled", set_enabled, NULL,
        OR_FILEINFO, "set \"On\" to enable count_memcookie, \"Off\" to disable"),
    AP_INIT_TAKE1("CountMemCookieName",set_cookie_name, NULL,
        OR_FILEINFO, "Name of cookie to lookup"),
    AP_INIT_TAKE1("CountMemCookieMemcachedAddrPort", set_memc_addr, NULL,
        OR_FILEINFO, "List of the memcached address( ip or host adresse(s) and port ':' separated). The addresses are ',' comma separated"),
    AP_INIT_TAKE1("CountMemCookieMemcachedObjectExpiry", set_memc_expiry, NULL,
        OR_FILEINFO, "expiry time of session object in memcached in seconds"),
    AP_INIT_TAKE1("CountMemCookieMemcachedTableSize", set_memc_table_size, NULL,
        OR_FILEINFO, "[deprecated] Max number of element in session table of memcached. 0 by default, no limit"),
    AP_INIT_FLAG("CountMemCookieSetHTTPHeader", set_setheader, NULL,
        OR_FILEINFO, "Set to \"On\" to set count information to http header. \"Off\" by default"),
    {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA count_memcookie_module = {
    STANDARD20_MODULE_STUFF,
    count_memcookie_create_dir_config,        /* create per-dir    config structures */
    NULL,                                     /* merge  per-dir    config structures */
    NULL,                                     /* create per-server config structures */
    NULL,                                     /* merge  per-server config structures */
    count_memcookie_cmds,                     /* table of config file commands       */
    count_memcookie_register_hooks            /* register hooks                      */
};

/*
 * vim:ts=4 et
 */
