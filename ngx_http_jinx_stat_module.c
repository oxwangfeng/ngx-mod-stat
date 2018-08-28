
/*
 * std@jd.com
 * www.jd.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define MAX_URI_SIZE 30


typedef struct {
} jinx_stat_loc_conf_t;


typedef struct {
    ngx_int_t       enable;
    ngx_int_t       jinx_stat_max;
    ngx_array_t     *stat_uri;
} jinx_stat_srv_conf_t;


typedef struct {
    ngx_shm_zone_t 	*zone;
    ngx_int_t 		enable;
} jinx_stat_main_conf_t;


typedef struct {
    ngx_slab_pool_t *shpool;
    ngx_int_t       *node_count;
    ngx_rbtree_t    *rbtree;
} jinx_stat_shdict_ctx_t;


typedef struct {
    u_char color;
    u_char padding[2];
    u_char len;
    ngx_uint_t reqs;
    ngx_uint_t rt5;
    ngx_uint_t rt10;
    ngx_uint_t rt20;
    ngx_uint_t rt50;
    ngx_uint_t rt100;
    ngx_uint_t rt200;
    ngx_uint_t rt500;
    ngx_uint_t rt1000;
    ngx_uint_t rt2000;
    ngx_uint_t rt5000;
    ngx_uint_t rt10000;
    ngx_uint_t rtx;
    ngx_uint_t usrt5;
    ngx_uint_t usrt10;
    ngx_uint_t usrt20;
    ngx_uint_t usrt50;
    ngx_uint_t usrt100;
    ngx_uint_t usrt200;
    ngx_uint_t usrt500;
    ngx_uint_t usrt1000;
    ngx_uint_t usrt2000;
    ngx_uint_t usrt5000;
    ngx_uint_t usrt10000;
    ngx_uint_t usrtx;
    ngx_uint_t hc200;
    ngx_uint_t hc301;
    ngx_uint_t hc400;
    ngx_uint_t hc404;
    ngx_uint_t hc405;
    ngx_uint_t hc415;
    ngx_uint_t hc500;
    ngx_uint_t hc502;
    ngx_uint_t hc2xx;
    ngx_uint_t hc3xx;
    ngx_uint_t hc4xx;
    ngx_uint_t hc5xx;
    ngx_uint_t hcxxx;
    ngx_uint_t traffic_in;
    ngx_uint_t traffic_out;
    u_char data[1];
} jinx_stat_node_t;


static ngx_rbtree_node_t *jinx_stat_host_lookup(ngx_rbtree_t *rbtree,
        ngx_str_t *key, uint32_t hash);
static void *jinx_stat_create_main_conf(ngx_conf_t *cf);
static void *jinx_stat_create_srv_conf(ngx_conf_t *cf);
static void *jinx_stat_create_loc_conf(ngx_conf_t *cf);
static char *jinx_stat_merge_srv_conf(ngx_conf_t *cf, void *parent,
        void *child);
static char *jinx_stat_shared_dict(ngx_conf_t *cf, void *conf, ngx_int_t jinx_stat_max);
static char *jinx_stat_out_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t jinx_stat_init(ngx_conf_t *cf);
static ngx_int_t jinx_set_stat_data(jinx_stat_node_t *jsn,
        ngx_http_variable_value_t *traffic_in_var,
        ngx_http_variable_value_t *traffic_out_var,
        ngx_http_variable_value_t *rt_var,
        ngx_http_variable_value_t *urt_var,
        ngx_http_variable_value_t *status_var);
static ngx_int_t jinx_stat_handle_node(ngx_http_request_t *r,
        jinx_stat_srv_conf_t 	*scf,
        jinx_stat_shdict_ctx_t *ctx,
        ngx_str_t key, uint32_t hash, ngx_int_t max,
        ngx_http_variable_value_t *traffic_in_var,
        ngx_http_variable_value_t *traffic_out_var,
        ngx_http_variable_value_t *rt_var,
        ngx_http_variable_value_t *urt_var,
        ngx_http_variable_value_t *status_var);
static char * jinx_set_stat_uri(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t jinx_stat_commands[] = {
    {
        ngx_string("jinx_stat"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(jinx_stat_srv_conf_t, enable),
        NULL
    },

    {
        ngx_string("jinx_stat_max"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
        ngx_conf_set_size_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(jinx_stat_srv_conf_t, jinx_stat_max),
        NULL
    },

    {
        ngx_string("jinx_stat_out"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        jinx_stat_out_set,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("jinx_stat_uri"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        jinx_set_stat_uri,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(jinx_stat_srv_conf_t, stat_uri),
        NULL
    },

    ngx_null_command
};


static ngx_str_t traffic_in_name = ngx_string("request_length");
static ngx_uint_t traffic_in_hash;

static ngx_str_t traffic_out_name = ngx_string("bytes_sent");
static ngx_uint_t traffic_out_hash;

static ngx_str_t rt_name = ngx_string("request_time");
static ngx_uint_t rt_hash;

static ngx_str_t status_name = ngx_string("status");
static ngx_uint_t status_hash;

static ngx_uint_t upstream_response_time_index;


static ngx_http_module_t jinx_stat_module_ctx = {
    NULL, 							/* preconfiguration */
    jinx_stat_init, 				/* postconfiguration */

    jinx_stat_create_main_conf, 	/* create main configuration */
    NULL, 							/* init main configuration */

    jinx_stat_create_srv_conf, 		/* create server configuration */
    jinx_stat_merge_srv_conf, 		/* merge server configuration */

    jinx_stat_create_loc_conf, 		/* create location configuration */
    NULL 							/* merge location configuration */
};


ngx_module_t ngx_http_jinx_stat_module = {
    NGX_MODULE_V1,
    &jinx_stat_module_ctx, 			/* module context */
    jinx_stat_commands, 			/* module directives */
    NGX_HTTP_MODULE, 				/* module type */
    NULL, 							/* init master */
    NULL, 							/* init module */
    NULL, 							/* init process */
    NULL, 							/* init thread */
    NULL, 							/* exit thread */
    NULL, 							/* exit process */
    NULL, 							/* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_jinx_stat_handler(ngx_http_request_t *r)
{
    jinx_stat_srv_conf_t 		*scf;
    jinx_stat_main_conf_t 		*mcf;
    jinx_stat_shdict_ctx_t 		*ctx;
    ngx_http_core_srv_conf_t  	*cscf;

    ngx_http_variable_value_t *traffic_in_var;
    ngx_http_variable_value_t *traffic_out_var;
    ngx_http_variable_value_t *rt_var;
    ngx_http_variable_value_t *status_var;
    ngx_http_variable_value_t *urt_var;

    ngx_str_t 	key;
    uint32_t 	hash;
    ngx_str_t 	uri_key;
    uint32_t 	urihash;

    urihash = 0;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "jinx stat handler");

    scf = ngx_http_get_module_srv_conf(r, ngx_http_jinx_stat_module);
    if (!scf->enable) {
        return NGX_OK;
    }

    if (r->headers_in.host == NULL || r->headers_in.host->key.len <= 0
            || r->headers_in.host->value.len <= 0) {
        return NGX_OK;
    }

    key = r->headers_in.host->value;
    mcf = ngx_http_get_module_main_conf(r, ngx_http_jinx_stat_module);
    ctx = mcf->zone->data;
    hash = ngx_crc32_short(key.data, key.len);

    traffic_in_var = ngx_http_get_variable(r, &traffic_in_name,
            traffic_in_hash);
    traffic_out_var = ngx_http_get_variable(r, &traffic_out_name,
            traffic_out_hash);
    rt_var = ngx_http_get_variable(r, &rt_name, rt_hash);
    status_var = ngx_http_get_variable(r, &status_name, status_hash);
    urt_var = ngx_http_get_indexed_variable(r, upstream_response_time_index);

    jinx_stat_handle_node(r, scf, ctx, key, hash, scf->jinx_stat_max,
            traffic_in_var, traffic_out_var, rt_var, urt_var, status_var);

#if 0
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "jsn %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d  %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
            jsn->reqs, jsn->traffic_in, jsn->traffic_out,
            jsn->rt5, jsn->rt10, jsn->rt20, jsn->rt50, jsn->rt100, jsn->rt200, jsn->rt500, jsn->rt1000, jsn->rt2000, jsn->rt5000, jsn->rt10000, jsn->rtx,
            jsn->usrt5, jsn->usrt10, jsn->usrt20, jsn->usrt50, jsn->usrt100, jsn->usrt200, jsn->usrt500, jsn->usrt1000, jsn->usrt2000, jsn->usrt5000, jsn->usrt10000, jsn->usrtx,
            jsn->hc200, jsn->hc301, jsn->hc400, jsn->hc404, jsn->hc405, jsn->hc415, jsn->hc500, jsn->hc502, jsn->hc2xx, jsn->hc3xx, jsn->hc4xx, jsn->hc5xx, jsn->hcxxx);
#endif

    uri_key.len = 0;
    ngx_uint_t i;
    ngx_str_t *uris;
    if (scf->stat_uri->nelts > 0) {
        uris = scf->stat_uri->elts;
        for (i = 0; i < scf->stat_uri->nelts; i++) {
            if (ngx_strncmp(&r->uri, &uris[i], uris[i].len) != 0) {
                continue;
            }

            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

            uri_key.len = cscf->server_name.len +  uris[i].len;
            uri_key.data = ngx_pcalloc(r->pool, uri_key.len);

            ngx_memcpy(uri_key.data, cscf->server_name.data, cscf->server_name.len);
            ngx_memcpy(uri_key.data + cscf->server_name.len, uris[i].data, uris[i].len);
            urihash = ngx_crc32_short(uri_key.data, uri_key.len);

            jinx_stat_handle_node(r, scf, ctx, uri_key, urihash, scf->jinx_stat_max,
                    traffic_in_var, traffic_out_var, rt_var, urt_var, status_var);
        }
    }

    return NGX_OK;
}


static ngx_int_t
jinx_stat_handle_node(ngx_http_request_t *r, jinx_stat_srv_conf_t 		*scf, jinx_stat_shdict_ctx_t *ctx,
        ngx_str_t key, uint32_t hash, ngx_int_t max,
        ngx_http_variable_value_t *traffic_in_var,
        ngx_http_variable_value_t *traffic_out_var,
        ngx_http_variable_value_t *rt_var, ngx_http_variable_value_t *urt_var,
        ngx_http_variable_value_t *status_var)
{
    ngx_rbtree_node_t 			*node;
    jinx_stat_node_t 			*jsn;
    size_t 		n;

    ngx_shmtx_lock(&ctx->shpool->mutex);
    node = jinx_stat_host_lookup(ctx->rbtree, &key, hash);

    if (node == NULL) {

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "jinx stat new key, node_count: %d;max:%d", *(ctx->node_count), max);

        //limit node count
        if ( *(ctx->node_count) >= max) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "jinx stat metric count more than: %ui", max);

            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_ERROR;
        }
        *(ctx->node_count) = *(ctx->node_count) + 1;

        n = offsetof(ngx_rbtree_node_t, color)
                + offsetof(jinx_stat_node_t, data)
                + key.len;


        node = ngx_slab_alloc_locked(ctx->shpool, n);
        if (node == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_HTTP_INSUFFICIENT_STORAGE;
        }

        jsn = (jinx_stat_node_t *) & node->color;
        node->key = hash;
        jsn->len = (u_char) key.len;

        jinx_set_stat_data(jsn, traffic_in_var, traffic_out_var, rt_var, urt_var,
                status_var);
        ngx_memcpy(jsn->data, key.data, key.len);
        ngx_rbtree_insert(ctx->rbtree, node);
    } else {

        jsn = (jinx_stat_node_t *) & node->color;
        jinx_set_stat_data(jsn, traffic_in_var, traffic_out_var, rt_var, urt_var,
                status_var);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_http_jinx_stat_out_handler(ngx_http_request_t *r)
{
    ngx_int_t 		rc, count, display_node;
    ngx_buf_t 		*b;
    ngx_chain_t 	out;
    ngx_uint_t 		content_length;
    ngx_str_t 		host;

    jinx_stat_main_conf_t 	*mcf;
    jinx_stat_shdict_ctx_t 	*ctx;
    ngx_rbtree_node_t 		*node, *sentinel, *tmp;
    jinx_stat_node_t 		*jsn;

    count = 0;
    display_node = 0;
    content_length = 0;

    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_jinx_stat_module);

    if (mcf->enable != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "need [jinx_stat on] within conf file");
        return NGX_HTTP_FORBIDDEN;
    }

    ctx = mcf->zone->data;

    // get host count
    ngx_shmtx_lock(&ctx->shpool->mutex);

    sentinel = ctx->rbtree->sentinel;
    node = ctx->rbtree->root;
    while (node != NULL && node->left != sentinel) {
        node = node->left;
    }

    while (node != NULL && node != sentinel) {
        count++;

        tmp = node->right;
        if (tmp != sentinel) {
            while (tmp->left != sentinel) {
                tmp = tmp->left;
            }
            node = tmp;
            continue;
        }

        tmp = node->parent;
        while (tmp != NULL && tmp != sentinel && tmp->right != NULL && node == tmp->right) {
            node = tmp;
            tmp = node->parent;
        }
        node = tmp;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    b = ngx_create_temp_buf(r->pool, count * 1280 + 2);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_cpymem(b->last, "{", 1);
    b->memory = 1;
    b->last_buf = 1;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    node = ctx->rbtree->root;
    while (node != NULL && node->left != sentinel) {
        node = node->left;
    }

    while (node != NULL && node != sentinel) {
        jsn = (jinx_stat_node_t *) & node->color;

        if (jsn->reqs > 0) {
            display_node++;
            host.len = jsn->len;
            host.data = jsn->data;
            b->last = ngx_sprintf(b->last, "\"%s\":{\"Reqs\": %ul,\"TrafficIn\": %ul,\"TrafficOut\": %ul,\"rt5\": %ul,\"rt10\": %ul,\"rt20\": %ul,\"rt50\": %ul,\"rt100\": %ul,\"rt200\": %ul,\"rt500\": %ul,\"rt1000\": %ul,\"rt2000\": %ul,\"rt5000\": %ul,\"rt10000\": %ul,\"rtx\": %ul,\"usrt5\": %ul,\"usrt10\": %ul,\"usrt20\": %ul,\"usrt50\": %ul,\"usrt100\": %ul,\"usrt200\": %ul,\"usrt500\": %ul,\"usrt1000\": %ul,\"usrt2000\": %ul,\"usrt5000\": %ul,\"usrt10000\": %ul,\"usrtx\": %ul,\"hc200\": %ul,\"hc301\": %ul,\"hc400\": %ul,\"hc404\": %ul,\"hc405\": %ul,\"hc415\": %ul,\"hc500\": %ul,\"hc502\": %ul,\"hc2xx\": %ul,\"hc3xx\": %ul,\"hc4xx\": %ul,\"hc5xx\": %ul,\"hcxxx\": %ul},",
                    host.data, jsn->reqs, jsn->traffic_in, jsn->traffic_out,
                    jsn->rt5, jsn->rt10, jsn->rt20, jsn->rt50, jsn->rt100, jsn->rt200, jsn->rt500, jsn->rt1000, jsn->rt2000, jsn->rt5000, jsn->rt10000, jsn->rtx,
                    jsn->usrt5, jsn->usrt10, jsn->usrt20, jsn->usrt50, jsn->usrt100, jsn->usrt200, jsn->usrt500, jsn->usrt1000, jsn->usrt2000, jsn->usrt5000, jsn->usrt10000, jsn->usrtx,
                    jsn->hc200, jsn->hc301, jsn->hc400, jsn->hc404, jsn->hc405, jsn->hc415, jsn->hc500, jsn->hc502, jsn->hc2xx, jsn->hc3xx, jsn->hc4xx, jsn->hc5xx, jsn->hcxxx);
        }

        tmp = node->right;
        if (tmp != sentinel) {
            while (tmp->left != sentinel) {
                tmp = tmp->left;
            }
            node = tmp;
            continue;
        }

        tmp = node->parent;
        while (tmp != NULL && tmp != sentinel && tmp->right != NULL && node == tmp->right) {
            node = tmp;
            tmp = node->parent;
        }
        node = tmp;
    }

    if (display_node > 0) {
        b->last = ngx_cpymem(b->last - 1, "}", 1);
    } else {
        b->last = ngx_cpymem(b->last, "}", 1);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    content_length = b->last - b->pos;

    ngx_str_set(&r->headers_out.content_type, "application/json");

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = content_length;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {

        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
jinx_set_stat_data(jinx_stat_node_t *jsn,
        ngx_http_variable_value_t *traffic_in_var,
        ngx_http_variable_value_t *traffic_out_var,
        ngx_http_variable_value_t *rt_var,
        ngx_http_variable_value_t *urt_var,
        ngx_http_variable_value_t *status_var)
{
    ngx_int_t res;

    if (!rt_var->not_found) {
        res = ngx_atoi(rt_var->data, rt_var->len);

        if (res < 5) {
            jsn->rt5++;
        } else if (res < 10) {
            jsn->rt10++;
        } else if (res < 20) {
            jsn->rt20++;
        } else if (res < 50) {
            jsn->rt50++;
        } else if (res < 100) {
            jsn->rt100++;
        } else if (res < 200) {
            jsn->rt200++;
        } else if (res < 500) {
            jsn->rt500++;
        } else if (res < 1000) {
            jsn->rt1000++;
        } else if (res < 2000) {
            jsn->rt2000++;
        } else if (res < 5000) {
            jsn->rt5000++;
        } else if (res < 10000) {
            jsn->rt10000++;
        } else {
            jsn->rtx++;
        }
    }

    if (!urt_var->not_found) {
        res = ngx_atoi(urt_var->data, urt_var->len);

        if (res < 5) {
            jsn->usrt5++;
        } else if (res < 10) {
            jsn->usrt10++;
        } else if (res < 20) {
            jsn->usrt20++;
        } else if (res < 50) {
            jsn->usrt50++;
        } else if (res < 100) {
            jsn->usrt100++;
        } else if (res < 200) {
            jsn->usrt200++;
        } else if (res < 500) {
            jsn->usrt500++;
        } else if (res < 1000) {
            jsn->usrt1000++;
        } else if (res < 2000) {
            jsn->usrt2000++;
        } else if (res < 5000) {
            jsn->usrt5000++;
        } else if (res < 10000) {
            jsn->usrt10000++;
        } else {
            jsn->usrtx++;
        }
    }

    if (!status_var->not_found) {
        res = ngx_atoi(status_var->data, status_var->len);

        if (res == 200) {
            jsn->hc200++;
        } else if (res == 301) {
            jsn->hc301++;
        } else if (res == 400) {
            jsn->hc400++;
        } else if (res == 404) {
            jsn->hc404++;
        } else if (res == 405) {
            jsn->hc405++;
        } else if (res == 415) {
            jsn->hc415++;
        } else if (res == 500) {
            jsn->hc500++;
        } else if (res == 502) {
            jsn->hc502++;
        } else if (res < 300) {
            jsn->hc2xx++;
        } else if (res < 400) {
            jsn->hc3xx++;
        } else if (res < 500) {
            jsn->hc4xx++;
        } else if (res < 600) {
            jsn->hc5xx++;
        } else {

            jsn->hcxxx++;
        }
    }

    if (!traffic_in_var->not_found) {
        jsn->traffic_in += ngx_atoi(traffic_in_var->data, traffic_in_var->len);
    }

    if (!traffic_out_var->not_found) {
        jsn->traffic_out += ngx_atoi(traffic_out_var->data, traffic_out_var->len);
    }

    jsn->reqs++;

    return NGX_OK;
}


static ngx_rbtree_node_t *
jinx_stat_host_lookup(ngx_rbtree_t *rbtree, ngx_str_t *key, uint32_t hash)
{
    ngx_int_t 			rc;
    ngx_rbtree_node_t 	*node, *sentinel;
    jinx_stat_node_t 	*lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (jinx_stat_node_t *) & node->color;

        rc = ngx_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {

            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
jinx_stat_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t 	**p;
    jinx_stat_node_t 	*lcn, *lcnt;

    for (; ; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (jinx_stat_node_t *) & node->color;
            lcnt = (jinx_stat_node_t *) & temp->color;

            p = (ngx_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                    ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {

            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
jinx_stat_shdict_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    jinx_stat_shdict_ctx_t 	*octx;
    jinx_stat_shdict_ctx_t 	*ctx;
    ngx_rbtree_node_t 		*sentinel;

    ctx = shm_zone->data;
    octx = data;

    if (octx) {
        ctx->rbtree = octx->rbtree;
        ctx->shpool = octx->shpool;
        ctx->node_count = octx->node_count;
        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    ctx->node_count  = ngx_slab_alloc(ctx->shpool, sizeof(ngx_int_t));
    if (ctx->node_count  == NULL) {
        return NGX_ERROR;
    }

    if (shm_zone->shm.exists) {
        ctx->rbtree = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->rbtree = ngx_slab_alloc(ctx->shpool, sizeof(ngx_rbtree_t));
    if (ctx->rbtree == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->rbtree;

    sentinel = ngx_slab_alloc(ctx->shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(ctx->rbtree, sentinel, jinx_stat_rbtree_insert_value);

    return NGX_OK;
}


char *
jinx_stat_shared_dict(ngx_conf_t *cf, void *conf, ngx_int_t jinx_stat_max)
{
    jinx_stat_main_conf_t 		*jsmcf;
    ssize_t 					size;
    ssize_t 					shm_size;
    ngx_shm_zone_t 				*zone;
    ngx_str_t 					name;
    jinx_stat_shdict_ctx_t 		*ctx;

    ngx_str_set(&name, "jinx_status");
    jsmcf = conf;

    size =  sizeof(ngx_slab_pool_t) + sizeof(ngx_int_t) + sizeof(ngx_rbtree_t) +
            jinx_stat_max * (sizeof(ngx_rbtree_node_t) + sizeof(jinx_stat_node_t));
    
#if 0  
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "jinx_stat_shared_dict value:%ui  %ui  %ui  %ui  %ui",
            sizeof(ngx_int_t) , sizeof(ngx_rbtree_t) , jinx_stat_max, sizeof(ngx_rbtree_node_t) , sizeof(jinx_stat_node_t) );
#endif
    
    //the min shm size is 8*page_size; 
    shm_size = size < (ssize_t) (8 * ngx_pagesize) ? (ssize_t) (8 * ngx_pagesize) : size ;

    zone = ngx_shared_memory_add(cf, &name,  shm_size,
            &ngx_http_jinx_stat_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(jinx_stat_shdict_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    if (zone->data) {
        ctx = zone->data;

        return NGX_CONF_ERROR;
    }

    zone->init = jinx_stat_shdict_init_zone;

    zone->data = ctx;
    jsmcf->zone = zone;

    return NGX_CONF_OK;
}


static char *
jinx_stat_out_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_jinx_stat_out_handler;

    return NGX_CONF_OK;
}


static void *
jinx_stat_create_main_conf(ngx_conf_t *cf)
{
    jinx_stat_main_conf_t *jsmcf;

    jsmcf = ngx_pcalloc(cf->pool, sizeof(jinx_stat_main_conf_t));
    if (jsmcf == NULL) {

        return NULL;
    }

    return jsmcf;
}


static void *
jinx_stat_create_srv_conf(ngx_conf_t *cf)
{
    jinx_stat_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(jinx_stat_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->jinx_stat_max = NGX_CONF_UNSET;
    conf->stat_uri = ngx_array_create(cf->pool, 10,  sizeof(ngx_str_t));

    return conf;
}


static char *
jinx_stat_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    jinx_stat_srv_conf_t 	*prev;
    jinx_stat_srv_conf_t 	*conf;
    jinx_stat_main_conf_t	*jsmcf;

    prev = parent;
    conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->jinx_stat_max, prev->jinx_stat_max, 10);

    if (prev->enable == 1 || conf->enable == 1) {
        jsmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_jinx_stat_module);
        jsmcf->enable = 1;
    }

    return NGX_CONF_OK;
}


static void *
jinx_stat_create_loc_conf(ngx_conf_t *cf)
{
    jinx_stat_loc_conf_t* local_conf;

    local_conf = ngx_pcalloc(cf->pool, sizeof(jinx_stat_loc_conf_t));

    if (local_conf == NULL) {
        return NULL;
    }

    return local_conf;
}


static ngx_int_t
jinx_stat_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt 		*h;
    ngx_http_core_main_conf_t 	*cmcf;
    jinx_stat_main_conf_t		*jsmcf;
    jinx_stat_srv_conf_t 		*scf;

    ngx_log_error(NGX_LOG_INFO, cf->log, 0, "jinx stat init");

    jsmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_jinx_stat_module);
    if (jsmcf->enable != 1) {
        return NGX_OK;
    }

    scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_jinx_stat_module);

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_jinx_stat_handler;

    traffic_in_hash = ngx_hash_key(traffic_in_name.data, traffic_in_name.len);

    traffic_out_hash = ngx_hash_key(traffic_out_name.data, traffic_out_name.len);

    rt_hash = ngx_hash_key(rt_name.data, rt_name.len);

    status_hash = ngx_hash_key(status_name.data, status_name.len);

    ngx_str_t urt_name = ngx_string("upstream_response_time");
    upstream_response_time_index = ngx_http_get_variable_index(cf, &urt_name);

    jinx_stat_shared_dict(cf, jsmcf, scf->jinx_stat_max);

    if (jsmcf->zone == NULL) {

        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                "jinx stat no dict specified within nginx.conf");
        return NGX_ERROR;
    }
    return NGX_OK;
}


static char *
jinx_set_stat_uri(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t         *value, *s;
    ngx_array_t      **a;
    ngx_conf_post_t   *post;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    s = ngx_array_push(*a);
    if (s == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    *s = value[1];

    if (s->len > MAX_URI_SIZE) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "plase keep stat uri %s lenth < %d", s->data, MAX_URI_SIZE);
        return NGX_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, s);
    }

    return NGX_CONF_OK;
}