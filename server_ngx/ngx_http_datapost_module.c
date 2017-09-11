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
#include <curl/curl.h>
#include <mysql/mysql.h>

typedef struct
{
    ngx_str_t datapost_control;
} ngx_http_datapost_loc_conf_t;

static void *ngx_http_datapost_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_datapost_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_datapost_handler(ngx_http_request_t *r);
static void ngx_http_request_body_process(ngx_http_request_t *r);

int handleData(char *, int);
static void construct_json(int);
static char *parseData(char *);
static int postData(char *, char *);
static size_t write_data(void *buffer, size_t size, size_t nmemb, void *stream);
static ngx_int_t job_send_header(ngx_http_request_t *);

static u_char *return_data;

static ngx_command_t ngx_http_datapost_commands[] = {
    {
    	ngx_string("datapost_control"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_datapost_control,
        NGX_HTTP_LOC_CONF_OFFSET,
    	offsetof(ngx_http_datapost_loc_conf_t, datapost_control),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_datapost_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_datapost_create_loc_conf,
    NULL
};

ngx_module_t ngx_http_datapost_module = {
    NGX_MODULE_V1,
    &ngx_http_datapost_module_ctx,
    ngx_http_datapost_commands,
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

static ngx_int_t ngx_http_datapost_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "ngx_http_datapost_module is called");
    if (!(r->method & NGX_HTTP_POST)) {
	return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_request_body_process);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "datapost_control: ngx_http_datapost_module is called");
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    	return rc;
    }
    if (r->main->count > 1)
	r->main->count = 1;
    //memset(bufferip, 0, sizeof(bufferip));
    return NGX_DONE;
}

static void *ngx_http_datapost_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_datapost_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_datapost_loc_conf_t));
    if (local_conf == NULL) {
    	return NGX_CONF_ERROR;
    }
    local_conf->datapost_control.data = NULL;
    local_conf->datapost_control.len = 0;
    return local_conf;
}

static char *ngx_http_datapost_control(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_datapost_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

static void ngx_http_request_body_process(ngx_http_request_t *r)
{
    int status = 1;
    ngx_chain_t *chain;
    char *nodeIp = NULL;
    
    ngx_buf_t *buf;
    u_char *str = NULL;
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
	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "datapost_control:no target this time\n");
       
    } else {
	ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "datapost_control:target is: %s\n", str);}
    
    if (str != NULL)
    { 
        nodeIp = parseData((char *)str);
         ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "datapost_control:nodeIp: %s\n", nodeIp);
        status = postData((char *)str, nodeIp);
    }
   
    construct_json(status);
    job_send_header(r);
}

static void construct_json(int status)
{
    cJSON *root;
    root = cJSON_CreateObject(); 
    cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(status));
    return_data = (u_char *)(cJSON_Print(root));
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

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "datapost_control: %s, %d\n", b->pos, ngx_strlen(return_data));    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = ngx_strlen(return_data);
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, &out);

}

static size_t write_data(void *buffer, size_t size, size_t nmemb, void *stream)
{
    strcpy(stream, buffer);
    return size * nmemb;
}

char *parseData(char *data)
{
    cJSON *root, *rootItem;
    int i, j;
    int targetNum;
    int workingLinkId;
    char *status = NULL;
    
    char *nodeIp = malloc(sizeof(char) * 18);
    root = cJSON_Parse(data);
    targetNum = cJSON_GetArraySize(root);
    for (i = 0; i < targetNum; i++)
    {
	rootItem= cJSON_GetArrayItem(root, i);
  	if (rootItem)
	{
	    if (i == 0)
	    {
		strcpy(nodeIp, cJSON_GetObjectItem(rootItem, "nodeIp")->valuestring);
	    }
  	    workingLinkId = cJSON_GetObjectItem(rootItem, "id")->valueint;
	    if (cJSON_GetObjectItem(rootItem, "status") != NULL)
	    {
		status = cJSON_GetObjectItem(rootItem, "status")->valuestring;
		j = handleData(status, workingLinkId);
	    }
	}
    }
    return nodeIp;
}

int handleData(char *status, int workingLinkId)
{
    char command[128] = {0};
    char *server = "localhost";
    char *user = "root";
    char *password = "algoblu";
    char *database = "test";

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
    if (strcmp(status, "add") == 0)	
    {    
   	sprintf(command, "INSERT INTO working_link_status(working_link_id, delay, loss, jitter) values(%d, 0, 0, 0)", workingLinkId);
    } else {
	sprintf(command, "DELETE FROM working_link_status where working_link_id = %d", workingLinkId);
    }

    iRet = mysql_query(&my_connection, command);
    if (iRet)
        return 1;
    memset(command, 0, sizeof(command));
    return 0;

}


int postData(char *data, char *nodeIp)
{
    long code = 0;
    int status = 0;
    CURL *curl;
    CURLcode res;
    cJSON *root;
    char *fptr = malloc(sizeof(char) * 16);
    char command[32] = {0};
	
    sprintf(command, "%s/ping", nodeIp);
    curl = curl_easy_init();
    if (!curl) 
    {
	free(fptr);
	return 1;
    }
	
    curl_easy_setopt(curl, CURLOPT_URL, command);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fptr);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	
    if (res != CURLE_OK || code > 400) 
    {
	free(fptr);
	curl_easy_cleanup(curl);
	return 1;
    }
	
    curl_easy_cleanup(curl);
    root = cJSON_Parse(fptr);

    status = cJSON_GetObjectItem(root, "status")->valueint;
    return status;
}


































