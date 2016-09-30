
/*
 * Copyright (C) Jinhua Tan
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include <nginx.h>
#include "ngx_http_lua_cache.h"
#include "ngx_http_lua_clfactory.h"
#include "ngx_http_lua_util.h"
#include "ngx_http_lua_exception.h"
#include "ngx_http_lua_common.h"


ngx_module_t ngx_http_lua_client_module;


typedef struct {
    void        **main_conf;
    void        **srv_conf;
    void        **loc_conf;

    ngx_log_t    *log;
    ngx_pool_t   *pool;
    lua_State    *lua;

    ngx_int_t              fd;
    ngx_connection_t      *connection;

    ngx_int_t           port;
    ngx_str_t           host;

} ngx_http_lua_client_main_conf_t;


typedef struct {
    ngx_int_t    len;
    ngx_uint_t   type;

} ngx_http_lua_client_header;


typedef struct {
    void        *data;

    ngx_pool_t   *pool;
    ngx_chain_t  *log_chain;

    ngx_uint_t    type;
    ngx_str_t     code_src;

    ngx_int_t              fd;
    ngx_http_request_t    *r;

} ngx_http_lua_client_ctx_connect_t;


#define LOG_STR "logs:\n"
#define LOG_LEN sizeof(LOG_STR)
#define BUFFER_SIZE 4096
#define HEADER_SIZE sizeof(ngx_http_lua_client_header)


#define NGX_HTTP_LUA_CLI_FILE         0x00000001
#define NGX_HTTP_LUA_CLI_CODE         0x00000002

#define NGX_HTTP_LUA_CLI_DEL_CONN(c)    \
    if (ngx_del_conn) { \
        ngx_del_conn(c, 0); \
    } else { \
        ngx_del_event(c->read, NGX_READ_EVENT, 0); \
    } \
    if (c->fd > 0) { \
        ngx_close_socket(c->fd); \
    }


static void *ngx_http_lua_client_create_main_conf(ngx_conf_t *cf);
ngx_int_t ngx_http_lua_client_init_worker(ngx_cycle_t *cycle);
void ngx_http_lua_client_exit_worker(ngx_cycle_t *cycle);
ngx_int_t ngx_http_lua_client_init_fake_conf(ngx_cycle_t *cycle,
    ngx_http_lua_client_main_conf_t *lcmcf);
static void ngx_http_lua_client_create_connect(ngx_event_t *ev);
static void ngx_http_lua_client_handler(ngx_event_t *ev);
ngx_int_t ngx_http_lua_client_read(ngx_http_lua_client_ctx_connect_t *cctx,
    ngx_int_t fd);
ngx_int_t ngx_http_lua_client_handler_code(ngx_http_lua_client_ctx_connect_t *cctx,
    lua_State *L, ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_client_by_chunk(lua_State *L,
    ngx_http_request_t *r);
ngx_chain_t *ngx_http_lua_client_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
void ngx_http_lua_log_client_error(ngx_log_t *log, ngx_uint_t level,
    u_char *buf, size_t len);
    

static ngx_command_t ngx_http_lua_client_cmds[] = {

    { ngx_string("lua_client_port"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_lua_client_main_conf_t, port),
      NULL },

    { ngx_string("lua_client_host"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_lua_client_main_conf_t, host),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_lua_client_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    ngx_http_lua_client_create_main_conf,   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};    


ngx_module_t ngx_http_lua_client_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_client_module_ctx,    /*  module context */
    ngx_http_lua_client_cmds,           /*  module directives */
    NGX_HTTP_MODULE,                    /*  module type */
    NULL,                               /*  init master */
    NULL,                               /*  init module */
    ngx_http_lua_client_init_worker,    /*  init process */
    NULL,                               /*  init thread */
    NULL,                               /*  exit thread */
    ngx_http_lua_client_exit_worker,    /*  exit process */
    NULL,                               /*  exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_lua_client_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_lua_client_main_conf_t    *lcmcf;

    lcmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_client_main_conf_t));
    if (lcmcf == NULL) {
        return NULL;
    }

    lcmcf->pool = cf->pool;
    lcmcf->log = cf->log;
    lcmcf->port = NGX_CONF_UNSET;

    return lcmcf;
}

ngx_int_t
ngx_http_lua_client_init_worker(ngx_cycle_t *cycle)
{
    ngx_int_t                         fd;
    ngx_core_conf_t                  *ccf;
    u_char                           *p = NULL;
    ngx_event_t                      *ev;
    ngx_connection_t                 *c;
    ngx_http_lua_client_main_conf_t  *lcmcf;
    ngx_http_lua_main_conf_t         *lmcf;
    struct sockaddr_in                server_sockaddr;
    ngx_int_t                         worker_num;
    ngx_int_t                         slot;

    lmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_lua_module);
    lcmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_lua_client_module);

    if (lmcf == NULL
        || lmcf->lua == NULL
        || lcmcf == NULL)
    {
        return NGX_OK;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    worker_num = ccf->worker_processes;
    slot = ngx_process_slot;

    /* init in the first child process slot */
    if (slot % worker_num == 0) {
        /* init socket */
        fd = ngx_socket(AF_INET, SOCK_STREAM, 0);
        if (fd == (ngx_socket_t) -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "[lua client] ngx_socket() failed");
            goto failed;
        }
        server_sockaddr.sin_family = AF_INET;

        if (lcmcf->port != NGX_CONF_UNSET) {
            server_sockaddr.sin_port = htons(lcmcf->port);
        } else {
            server_sockaddr.sin_port = htons(8220);
        }

        if (lcmcf->host.len != 0) {
            server_sockaddr.sin_addr.s_addr = ngx_inet_addr(lcmcf->host.data, lcmcf->host.len);
        } else {
            server_sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        }

        if (bind(fd, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "[lua client] bind() failed");
            goto failed;
        }

        if (listen(fd, NGX_LISTEN_BACKLOG) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "[lua client] listen() failed");
            goto failed;
        }

        /* succtxess open fifo */
        p = ngx_alloc(sizeof(ngx_event_t) + sizeof(ngx_connection_t),
                  lcmcf->log);
        if (p == NULL) {
            goto failed;
        }

        ev = (ngx_event_t *) p;
        ngx_memzero(ev, sizeof(ngx_event_t));

        p += sizeof(ngx_event_t);
        c = (ngx_connection_t *) p;
        ngx_memzero(c, sizeof(ngx_connection_t));

        lcmcf->fd = fd;
        lcmcf->connection = c;
        lcmcf->lua = ngx_http_lua_init_vm(NULL, cycle, cycle->pool, lmcf,
                                         lcmcf->log, NULL);

        ngx_http_lua_client_init_fake_conf(cycle, lcmcf);

        c->fd = fd;
        c->data = lcmcf;
        c->read = ev;
        c->write = ev;

        ev->active = 0;
        ev->data = c;
        ev->handler = ngx_http_lua_client_create_connect;
        ev->log = lcmcf->log;
        if (ngx_add_event(ev, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "[lua client] ngx_add_event() failed");
        }
    }

    return NGX_OK;

failed:
    if (p) {
        ngx_free(p);
    }
    if (fd > 0) {
        ngx_close_socket(fd);
    }

    return NGX_OK;
}

void
ngx_http_lua_client_exit_worker(ngx_cycle_t *cycle)
{
    ngx_core_conf_t                  *ccf;
    ngx_http_lua_client_main_conf_t  *lcmcf;
    ngx_int_t                         worker_num;
    ngx_int_t                         slot;

    lcmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_lua_client_module);

    if (lcmcf == NULL)
    {
        return;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    worker_num = ccf->worker_processes;
    slot = ngx_process_slot;

    /* exit in the first child process slot */
    if (slot % worker_num == 0) {
        if (lcmcf->fd > 0) {
            NGX_HTTP_LUA_CLI_DEL_CONN(lcmcf->connection);
        }
    }

    return;
}

ngx_int_t 
ngx_http_lua_client_init_fake_conf(ngx_cycle_t *cycle,
    ngx_http_lua_client_main_conf_t *lcmcf)
{
    char                        *rv;
    void                        *cur, *prev;
    ngx_uint_t                   i;
    ngx_conf_t                   conf;
    ngx_cycle_t                 *fake_cycle;
    ngx_open_file_t             *file, *ofile;
    ngx_list_part_t             *part;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t         *conf_ctx, http_ctx;

    conf_ctx = ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index]);
    http_ctx.main_conf = conf_ctx->main_conf;

    ngx_memzero(&conf, sizeof(ngx_conf_t));

    conf.temp_pool = ngx_create_pool(NGX_CYCLE_POOL_SIZE, cycle->log);
    if (conf.temp_pool == NULL) {
        return NGX_ERROR;
    }

    conf.temp_pool->log = cycle->log;

    fake_cycle = ngx_palloc(cycle->pool, sizeof(ngx_cycle_t));
    if (fake_cycle == NULL) {
        goto failed;
    }

    ngx_memcpy(fake_cycle, cycle, sizeof(ngx_cycle_t));

#if defined(nginx_version) && nginx_version >= 9007

    ngx_queue_init(&fake_cycle->reusable_connections_queue);

#endif

    if (ngx_array_init(&fake_cycle->listening, cycle->pool,
                       cycle->listening.nelts || 1,
                       sizeof(ngx_listening_t))
        != NGX_OK)
    {
        goto failed;
    }

#if defined(nginx_version) && nginx_version >= 1003007

    if (ngx_array_init(&fake_cycle->paths, cycle->pool, cycle->paths.nelts || 1,
                       sizeof(ngx_path_t *))
        != NGX_OK)
    {
        goto failed;
    }

#endif

    part = &cycle->open_files.part;
    ofile = part->elts;

    if (ngx_list_init(&fake_cycle->open_files, cycle->pool, part->nelts || 1,
                      sizeof(ngx_open_file_t))
        != NGX_OK)
    {
        goto failed;
    }

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            ofile = part->elts;
            i = 0;
        }

        file = ngx_list_push(&fake_cycle->open_files);
        if (file == NULL) {
            goto failed;
        }

        ngx_memcpy(file, ofile, sizeof(ngx_open_file_t));
    }

    if (ngx_list_init(&fake_cycle->shared_memory, cycle->pool, 1,
                      sizeof(ngx_shm_zone_t))
        != NGX_OK)
    {
        goto failed;
    }

    conf.ctx = &http_ctx;
    conf.cycle = fake_cycle;
    conf.pool = fake_cycle->pool;
    conf.log = cycle->log;

    http_ctx.loc_conf = ngx_pcalloc(conf.pool,
                                    sizeof(void *) * ngx_http_max_module);
    if (http_ctx.loc_conf == NULL) {
        return NGX_ERROR;
    }

    http_ctx.srv_conf = ngx_pcalloc(conf.pool,
                                    sizeof(void *) * ngx_http_max_module);
    if (http_ctx.srv_conf == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_srv_conf) {
            cur = module->create_srv_conf(&conf);
            if (cur == NULL) {
                return NGX_ERROR;
            }

            if (module->merge_srv_conf) {
                prev = module->create_srv_conf(&conf);
                if (prev == NULL) {
                    return NGX_ERROR;
                }

                rv = module->merge_srv_conf(&conf, prev, cur);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }

            http_ctx.srv_conf[ngx_modules[i]->ctx_index] = cur;
        }

        if (module->create_loc_conf) {
            cur = module->create_loc_conf(&conf);
            if (cur == NULL) {
                return NGX_ERROR;
            }

            if (module->merge_loc_conf) {
                prev = module->create_loc_conf(&conf);
                if (prev == NULL) {
                    return NGX_ERROR;
                }

                rv = module->merge_loc_conf(&conf, prev, cur);
                if (rv != NGX_CONF_OK) {
                    goto failed;
                }
            }

            http_ctx.loc_conf[ngx_modules[i]->ctx_index] = cur;
        }
    }


    lcmcf->main_conf = http_ctx.main_conf;
    lcmcf->srv_conf = http_ctx.srv_conf;
    lcmcf->loc_conf = http_ctx.loc_conf;

    return NGX_OK;

failed:

    if (conf.temp_pool) {
        ngx_destroy_pool(conf.temp_pool);
    }

    return NGX_ERROR;
}

static void
ngx_http_lua_client_create_connect(ngx_event_t *ev)
{
    ngx_connection_t        *c = NULL;
    ngx_pool_t              *pool = NULL;
    u_char                  *p = NULL;

    ngx_connection_t                    *oc;
    ngx_http_lua_client_main_conf_t     *lcmcf;
    ngx_http_lua_client_ctx_connect_t   *cctx;
    ngx_event_t                         *conn_ev;
    ngx_int_t                            conn_fd;

    struct sockaddr_in          cli_addr;
    socklen_t                   socklen;
    socklen = NGX_SOCKADDRLEN;

    oc = (ngx_connection_t *) ev->data;
    lcmcf = oc->data;

    conn_fd = accept(lcmcf->fd, (struct sockaddr*)&cli_addr, &socklen);
    if (conn_fd < 0)
    {
        //TODO:log
        return;
    }
    
    pool = ngx_create_pool(512, lcmcf->log);
    if (pool == NULL) {
        goto failed;
    }

    p = ngx_palloc(pool, (sizeof(ngx_http_lua_client_ctx_connect_t) + sizeof(ngx_event_t)));
    if (p == NULL) {
        goto failed;
    }

    cctx = (ngx_http_lua_client_ctx_connect_t *) p;
    ngx_memzero(cctx, sizeof(ngx_http_lua_client_ctx_connect_t));

    p += sizeof(ngx_http_lua_client_ctx_connect_t);
    conn_ev = (ngx_event_t *) p;
    ngx_memzero(conn_ev, sizeof(ngx_event_t));

    c = ngx_http_lua_create_fake_connection(pool);
    if (c == NULL) {
        goto failed;
    }

    c->log->writer = ngx_http_lua_log_client_error;
    c->log->data = cctx;
    /* highest level */
    c->log->log_level = NGX_LOG_DEBUG;

    c->fd = conn_fd;
    c->error = 0;
    c->send_chain = ngx_http_lua_client_send_chain;
    c->read = conn_ev;
    c->write = conn_ev;
    c->data = cctx;

    cctx->fd = conn_fd;
    cctx->data = lcmcf;
    cctx->pool = pool;

    conn_ev->active = 0;
    conn_ev->data = c;
    conn_ev->handler = ngx_http_lua_client_handler;
    conn_ev->log = ev->log;

    ngx_http_lua_log_client_error(c->log, 0, LOG_STR, LOG_LEN);

    if (ngx_add_event(conn_ev, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, lcmcf->log, ngx_errno, "[lua client] ngx_add_event() failed");
    }
    return;

failed:
    if (pool) {
        ngx_destroy_pool(pool);
    }
    if (conn_fd > 0) {
        ngx_close_socket(conn_fd);
    }
    return;
}

static void
ngx_http_lua_client_handler(ngx_event_t *ev)
{
    ngx_int_t                rc;
    ngx_connection_t        *c = NULL;
    ngx_http_request_t      *r = NULL;

    ngx_http_lua_client_main_conf_t      *lcmcf;
    ngx_http_lua_client_ctx_connect_t    *cctx;
    
    c = (ngx_connection_t *) ev->data;
    cctx = (ngx_http_lua_client_ctx_connect_t *) c->data;
    lcmcf = (ngx_http_lua_client_main_conf_t *)cctx->data;

    /* read the input content */
    rc = ngx_http_lua_client_read(cctx, c->fd);
    if (rc == NGX_ERROR) {
        //TODO:log - read nothing
        goto failed;
    }

    r = ngx_http_lua_create_fake_request(c);
    if (r == NULL) {
        goto failed;
    }

    r->main_conf = lcmcf->main_conf;
    r->srv_conf = lcmcf->srv_conf;
    r->loc_conf = lcmcf->loc_conf;

    rc = ngx_http_lua_client_handler_code(cctx, lcmcf->lua, r);
    if (rc == NGX_ERROR) {
        goto failed;
    }

    return;

failed:
    if (c) {
        ngx_http_lua_client_send_chain(c, cctx->log_chain, 10);
        NGX_HTTP_LUA_CLI_DEL_CONN(c);
        ngx_http_lua_close_fake_connection(c);
    }
    return;
}

ngx_int_t
ngx_http_lua_client_read(ngx_http_lua_client_ctx_connect_t *cctx, ngx_int_t fd)
{
    u_char                       buf[BUFFER_SIZE];
    ngx_http_lua_client_header  *h;
    u_char                      *p;
    
    ngx_memzero(buf, BUFFER_SIZE);

    recv(fd, buf, BUFFER_SIZE, 0);

    h = (ngx_http_lua_client_header *)buf;
    if (h->len > (ngx_int_t) (BUFFER_SIZE - HEADER_SIZE)) {
        /* too long*/
        return NGX_ERROR;
    }

    p = buf + HEADER_SIZE;

    cctx->type = h->type;
    cctx->code_src.data = ngx_palloc(cctx->pool, h->len);
    if (cctx->code_src.data == NULL) {
        return NGX_ERROR;
    }

    ngx_copy(cctx->code_src.data, p, h->len);
    cctx->code_src.len = h->len;
    
    return NGX_OK;
}


ngx_int_t
ngx_http_lua_client_handler_code(ngx_http_lua_client_ctx_connect_t *cctx,
    lua_State *L, ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    char                        *err;

    rc = ngx_http_lua_clfactory_loadbuffer(L, (char *) cctx->code_src.data, cctx->code_src.len, "push code");

    if (rc != 0) {
        if (rc == LUA_ERRMEM) {
            err = "memory allocation error";
        } else {
            if (lua_isstring(L, -1)) {
                err = (char *) lua_tostring(L, -1);

            } else {
                err = "unknown error";
            }
        }

        goto error;
    }
    rc = lua_pcall(L, 0, 1, 0);
    if (rc != 0) {
        err = "bad clfactory";
        goto error;
    }

    return ngx_http_lua_client_by_chunk(L, r);
error:
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "lua coroutine: %s",
                              err);
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_lua_client_by_chunk(lua_State *L, ngx_http_request_t *r)
{
    int                                 co_ref;
    lua_State                          *co;
    ngx_int_t                           rc;
    ngx_connection_t                   *c;
    ngx_http_lua_ctx_t                 *ctx;
    ngx_http_lua_client_ctx_connect_t  *cctx;

    c = r->connection;
 
    co = ngx_http_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine to handle request");

        return NGX_ERROR;
    }

    lua_xmove(L, co, 1);

    ngx_http_lua_get_globals_table(co);
    lua_setfenv(co, -2);

    ngx_http_lua_set_req(co, r);

    ctx = ngx_http_lua_create_ctx(r);
    if (ctx == NULL) {
        goto failed;
    }

    ctx->cur_co_ctx = &ctx->entry_co_ctx;

    ctx->entered_content_phase = 1;
    ctx->context = NGX_HTTP_LUA_CONTEXT_CONTENT;

    r->read_event_handler = ngx_http_block_reading;

    ctx->cur_co_ctx->co_ref = co_ref;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_status = NGX_HTTP_LUA_CO_RUNNING;

    ngx_http_lua_set_req(co, r);

    rc = ngx_http_lua_run_thread(L, r, ctx, 0); //TODO: enbable add args while execute file

    if (rc == NGX_ERROR || rc >= NGX_OK) {
        /* do nothing */

    } else if (rc == NGX_AGAIN) {
        rc = ngx_http_lua_content_run_posted_threads(L, r, ctx, 0);

    } else if (rc == NGX_DONE) {
        rc = ngx_http_lua_content_run_posted_threads(L, r, ctx, 1);

    } else {
        rc = NGX_OK;
    }

    cctx = c->log->data;
    ngx_http_lua_client_send_chain(c, cctx->log_chain, 10);
    /* reset to fake connection */
    NGX_HTTP_LUA_CLI_DEL_CONN(c);
    r->connection->fd = -1;
    ngx_http_lua_finalize_request(r, rc);

    return NGX_OK;

failed:

    if (co_ref && co) {
        lua_pushlightuserdata(co, &ngx_http_lua_coroutines_key);
        lua_rawget(co, LUA_REGISTRYINDEX);
        luaL_unref(co, -1, co_ref);
        lua_settop(co, 0);
    }

    if (ctx->vm_state) {
        ngx_http_lua_cleanup_vm(ctx->vm_state);
    }

    if (c) {
        NGX_HTTP_LUA_CLI_DEL_CONN(c);
        ngx_http_lua_close_fake_connection(c);
    }

    return NGX_ERROR;
}


ngx_chain_t *
ngx_http_lua_client_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    ngx_int_t                    fd;
    ngx_http_lua_client_header  *h;
    u_char                      *s;
    ngx_chain_t                 *p;
    ngx_int_t                    len = 0;

    p = in;
    while (p) {
        len += p->buf->last - p->buf->pos;
        p = p->next;
    }

    fd = c->fd;
    s = ngx_palloc(c->pool, len + HEADER_SIZE);
    if (s == NULL) {
        //TODO: log
        return in;
    }
    h = (ngx_http_lua_client_header *) s;
    h->len = len;

    len = HEADER_SIZE;
    while (in) {
        ngx_memmove(s + len, in->buf->pos, in->buf->last - in->buf->pos);
        len += in->buf->last - in->buf->pos;
        in = in->next;
    }

    if (send(fd, s, len, 0) == -1) {
        //TODO: error
    }
    
    return in;
}

void ngx_http_lua_log_client_error(ngx_log_t *log, ngx_uint_t level,
    u_char *buf, size_t len)
{
    ngx_http_lua_client_ctx_connect_t   *cctx;
    ngx_chain_t                         *in, *cl;
    ngx_chain_t                        **ll;
    ngx_pool_t                          *pool;

    cctx = log->data;
    pool = cctx->pool;
    in = ngx_alloc_chain_link(pool);
    if (in == NULL) {
        return;
    }
    in->buf = len ? ngx_create_temp_buf(pool, len) : ngx_calloc_buf(pool);
    if (in->buf == NULL) {
        return;
    }

    in->next = NULL;

    in->buf->last = ngx_copy(in->buf->last, (u_char *) buf, len);

    for (cl = cctx->log_chain, ll = &cctx->log_chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    *ll = in;

    return;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
