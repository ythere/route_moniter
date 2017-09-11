#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <math.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "cJSON.h"


#define UCHAR unsigned char
#define USHORT unsigned short
#define UINT unsigned int

#define MONITERFILE "/root/yttest/moniter.conf"
#define SERVERFILE "/root/yttest/serverip.conf"
#define PIDFILE "/tmp/pidfile"

typedef struct 
{
    ngx_str_t ping_control;
} ngx_http_ping_loc_conf_t;

u_char *json_data;

static ngx_int_t job_send_header(ngx_http_request_t *r);
static void *ngx_http_ping_create_loc_conf(ngx_conf_t *cf);
//static char *ngx_http_ping_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_ping_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ping_handler(ngx_http_request_t *r);
static void ngx_http_request_body_process(ngx_http_request_t *r);

void constructResult(int );
static int parseJson(u_char *, ngx_http_request_t *);

static ngx_command_t ngx_http_ping_commands[] = {
    {
	ngx_string("ping_control"),
	NGX_HTTP_LOC_CONF| NGX_CONF_TAKE1,
	ngx_http_ping_control,
	NGX_HTTP_LOC_CONF_OFFSET,
	offsetof(ngx_http_ping_loc_conf_t, ping_control),
	NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_ping_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_ping_create_loc_conf,
    //ngx_http_ping_merge_loc_conf
    NULL
};

ngx_module_t ngx_http_ping_module = {
    NGX_MODULE_V1,
    &ngx_http_ping_module_ctx,
    ngx_http_ping_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_ping_handler(ngx_http_request_t *r)
{
    
    ngx_int_t rc;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ngx_http_ping_handler is called\n");
    
    /* we just response to the 'POST' requests */
    if (!(r->method & NGX_HTTP_POST))
    {
	return NGX_HTTP_NOT_ALLOWED;
    }
    
    rc = ngx_http_read_client_request_body(r, ngx_http_request_body_process);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "rc >= ngxhttpspecial\n");
	return rc;
    }
    if (r->main->count > 1)
	r->main->count = 1;
    //ngx_close_connection(r->connection); 
    //memset(json_data, 0, sizeof(json_data));
    return NGX_DONE; 
}

static void *ngx_http_ping_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ping_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ping_loc_conf_t));
    if (local_conf == NULL){
	return NGX_CONF_ERROR;
    }
    local_conf->ping_control.data = NULL;
    local_conf->ping_control.len = 0;
    return local_conf;
}

static char *ngx_http_ping_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ping_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;   
}

static void ngx_http_request_body_process(ngx_http_request_t *r)
{
    ngx_chain_t *chain;
    ngx_buf_t *buf;
    u_char *str;
    int status = 0;
    char buffer[256] = "";
    FILE *fp, *pidfp;
    chain = r->request_body->bufs;
    buf = chain->buf;
    //str = buf->pos;
    while (chain != NULL) {
	strncat(buffer, (char *)chain->buf->pos, (chain->buf->last - chain->buf->pos));
	chain = chain->next;
    }
    str = (u_char *)buffer;
    if (buf == NULL) {
	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ping_control:no target this time\n");   
	status = 1;
    }
    else {
    	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ping_control:ping target %s\n", buf->pos);
    	status = parseJson(str, r);  
    } 
    constructResult(status);
    if(status == 0)
    {
	char *serverIp = inet_ntoa(((struct sockaddr_in *)(r->connection->sockaddr))->sin_addr);
        fp = fopen(SERVERFILE, "w");
        fputs(serverIp, fp);
        fclose(fp);
        fp = NULL;

        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ping_control:serverip %s!\n", serverIp);   	

        pidfp = fopen(PIDFILE, "r");
 	char buffer[8] = {0};
        char cmd[32] = {0};
        fgets(buffer, sizeof(buffer), pidfp);
        buffer[strlen(buffer)] = '\0';
  	fclose(pidfp);
   	char *pid = buffer;
        sprintf(cmd, "kill -s USR1 %s", pid);
	system(cmd);
	
    }
    job_send_header(r);

}

static ngx_int_t job_send_header(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_str_set(&r->headers_out.content_type, "text/html");
    
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out.buf = b;
    out.next = NULL;
    b->pos = json_data;
    b->last = json_data + ngx_strlen(json_data);
    b->memory = 1;
    b->last_buf = 1;

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ping_control:%s, %d\n", b->pos, ngx_strlen(json_data));
    
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_strlen(json_data);
    rc = ngx_http_send_header(r);
   // if (rc != NGX_OK) {
   if (rc == NGX_ERROR || rc > NGX_OK || r->header_only){
        return rc;
    } 
    return ngx_http_output_filter(r, &out);

}

static int parseJson(u_char *data, ngx_http_request_t *r)
{
    char buffer[128];
    sprintf(buffer, "echo '%s' > %s", data, MONITERFILE);
    system(buffer);
    return 0;
}


void constructResult(int status)
{
    cJSON *root;
	
    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "status", status);
    json_data = (u_char *)cJSON_Print(root);
}












