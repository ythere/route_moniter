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
#include "cJSON.h"
#include <mysql/mysql.h>

#define MONITER_DATABASE "/tmp/moniter_database.db"
#define MONITER_DATABASE_SERVER "/tmp/moniter_database_server.db"

/*
struct SmoniterData
{
    int m_nodeId;
    char *m_ip;
    long m_avg;
    long m_mdev;
    int m_loss;
    struct SmoniterData *next;
};
*/
typedef struct
{
    ngx_str_t moniter_control;
} ngx_http_moniter_loc_conf_t;

static void *ngx_http_moniter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_moniter_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_moniter_handler(ngx_http_request_t *r);
static void ngx_http_request_body_process(ngx_http_request_t *r);

static ngx_int_t job_send_header(ngx_http_request_t *r);
static void construct_json(int );



static int parseMoniter(char *moniterData, ngx_http_request_t *);



static u_char *return_data;

char *server = "localhost";
char *user = "root";
char *password = "algoblu";
char *database = "test";




static ngx_command_t ngx_http_moniter_commands[] = {
    {
    	ngx_string("moniter_control"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_moniter_control,
        NGX_HTTP_LOC_CONF_OFFSET,
    	offsetof(ngx_http_moniter_loc_conf_t, moniter_control),
	NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_moniter_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_moniter_create_loc_conf,
    NULL
};

ngx_module_t ngx_http_moniter_module = {
    NGX_MODULE_V1,
    &ngx_http_moniter_module_ctx,
    ngx_http_moniter_commands,
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

static ngx_int_t ngx_http_moniter_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ngx_http_moniter_module is called");
    if (!(r->method & NGX_HTTP_POST)) {
	return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_request_body_process);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "moniter_control: ngx_http_moniter_module is called");
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    	return rc;
    }
    if (r->main->count > 1)
	r->main->count = 1;
    return NGX_DONE;
}

static void *ngx_http_moniter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_moniter_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_moniter_loc_conf_t));
    if (local_conf == NULL) {
    	return NGX_CONF_ERROR;
    }
    local_conf->moniter_control.data = NULL;
    local_conf->moniter_control.len = 0;
    return local_conf;
}

static char *ngx_http_moniter_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_moniter_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

static void ngx_http_request_body_process(ngx_http_request_t *r)
{
    /* Get current time */
    int i = 0;
    ngx_chain_t *chain;
    ngx_buf_t *buf;
    u_char *str;
    char buffer[128] = "";
    chain = r->request_body->bufs;
    buf = chain->buf;
    //str = buf->pos;
    while (chain != NULL) {
	strncat(buffer, (char *)chain->buf->pos, (chain->buf->last - chain->buf->pos));
 	chain = chain->next;
    }
    str = (u_char *)buffer;
    
    if (buf == NULL) {
	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "moniter_control:no target this time\n");
       
    } else {
	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "moniter_control:target is: %s\n", str);    	
    }
    
    i = parseMoniter((char *)str, r);
    
    construct_json(i);
    job_send_header(r);
}

static void construct_json(int status)
{
   // char event[20] = {0};
    cJSON *jsonroot = cJSON_CreateObject();
    //cJSON *dir = cJSON_CreateObject();

    cJSON_AddNumberToObject(jsonroot, "Status", status);
 /*   
    switch(return_status){
    case 0:
	strcpy(event, "success");
	break;
    case 1:
	strcpy(event, "sqlite_open wrong");
 	break;
    case 2:
	strcpy(event, "sqlite_exec find target ip wrong");
	break;
    case 3:
	strcpy(event, "sqlite_exec insert into database wrong");
	break;
    }
    memset(event, 0, sizeof(event));*/
    return_data = (u_char *)cJSON_Print(jsonroot);
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
    b->pos = return_data;
    b->last = return_data + ngx_strlen(return_data);
    b->memory = 1;
    b->last_buf = 1;

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "moniter_control: %s, %d\n", b->pos, ngx_strlen(return_data));   
     r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_strlen(return_data);
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, &out);

}

static int parseMoniter(char *moniterData, ngx_http_request_t *r)
{
    cJSON *root;
    int id, loss;
    double  avg, mdev;
    char command[256] = {0};
    int status = 0;    
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "parse data begin\n");
    root = cJSON_Parse(moniterData);
    id = cJSON_GetObjectItem(root, "id")->valueint;
    avg = cJSON_GetObjectItem(root, "avg")->valueint;
    mdev = cJSON_GetObjectItem(root, "mdev")->valuedouble;
    loss = cJSON_GetObjectItem(root, "loss")->valueint;


    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "data %d %f %f %d\n",id, avg, mdev, loss); 
    
    MYSQL my_connection, *conn_ptr;
    unsigned int uiTimeout = 3;
    int iRet;
    
    conn_ptr = mysql_init(&my_connection);

    if (!conn_ptr)
    {
        return 1;
    }
    iRet = mysql_options(&my_connection, MYSQL_OPT_CONNECT_TIMEOUT, (const char *)&uiTimeout);
    if (iRet)
    {
        return 1;
    }          
    conn_ptr = mysql_real_connect(&my_connection, server, user, password, database, 0, NULL, 0);
    if (!conn_ptr)
 	return 1;
    sprintf(command, "update working_link_status set delay = '%d', loss = '%d', jitter = '%f' where working_link_id = '%d'", (int)avg, loss, mdev, id);
    iRet = mysql_query(&my_connection, command);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "error %d %s\n",mysql_errno(&my_connection), mysql_error(&my_connection));
    if (iRet)
	status = 1;
    memset(command, 0, sizeof(command));
    
    return status;
}























