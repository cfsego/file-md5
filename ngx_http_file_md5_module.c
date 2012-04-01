#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

static ngx_int_t ngx_http_file_md5_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_file_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_module_t  ngx_http_file_md5_ctx = {
    ngx_http_file_md5_add_variables,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_file_md5_module = {
    NGX_MODULE_V1,
    &ngx_http_file_md5_ctx,                /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_file_md5_add_variables(ngx_conf_t *cf)
{
    ngx_str_t             vname = ngx_string("file_md5");
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &vname, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_file_md5_variable;
    var->data = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_file_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    off_t                      size, n, i;
    u_char                    *last, buf[8192], md5[16];
    size_t                     root, len;
    ngx_str_t                  path;
    ngx_log_t                 *log;
    ngx_int_t                  bval;
    ngx_md5_t                  ctx;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_ERROR;
    }

    log = r->connection->log;

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;
    
    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_md5_init(&ctx);
    size = of.size;
    len = 8192;

    while (size > 0) {

        if ((off_t) len > size) {
            len = (size_t) size;
        }

        n = ngx_read_fd(of.fd, buf, len);

        if (n == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_read_fd_n "failed");
            return NGX_ERROR;
        }

        if ((size_t) n != len) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_read_fd_n " has read only %z of %uz",
                          n, size);
            return NGX_ERROR;
        }

        ngx_md5_update(&ctx, buf, len);

        size -= n;
    }

    ngx_md5_final(md5, &ctx);

    last = v->data = ngx_palloc(r->pool, 32);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < 16; i++) {
        bval = md5[i];
        last = ngx_sprintf(last, "%02xi", bval);
    }

    v->no_cacheable = 0;
    v->valid = 1;
    v->not_found = 0;
    v->len = 32;

    return NGX_OK;
}
