#include "cJSON.h"
#include "nodemoniter.h"

#define PIDFILE "/tmp/pidfile"
#define MONITERFILE "/root/yttest/moniter.conf"
#define SERVERFILE "/root/yttest/serverip.conf"
#define SHELLROUTE "/root/yttest/moniterip.sh"

int targetNum = 0;
char *jsonData = NULL;
struct StargetData *ptarget = NULL;
pthread_t ntid[10];
FILE *fp[10];
char *serverIp = NULL;

void initDaemon();
char *parseConfig();
void parseJson(char *);
void threadProcess();
void constructTargetStruct(struct StargetData *data);
void *processMoniterData(void *arg);
void restartConfig();

extern void parseJson(char *);

void freeData()
{
    int i;
    if (jsonData != NULL)
        free(jsonData);
    ptarget = NULL;
    for (i = 0; i < targetNum; i++)
    {
        pthread_cancel(ntid[i]);
    }
}

void restartConfig()
{
    freeData();
    
    jsonData = parseConfig();
    parseJson(jsonData);
}

//线程发包函数
void *processMoniterData(void *arg)
{
    char data[3][16];
    cJSON *root;
    struct StargetData *pdata = (struct StargetData *)arg;
    char cmd[64] = {0};
    char buffer[64] = {0};
    int i, j = 0;
    while(1)
    {
        for (i = 0; i < 3; i++)
            memset(data[i], 0, sizeof(data[i]));
        j = 0;
        memset(cmd, 0, sizeof(cmd));

        //根据间隔循环发包探测线路
        sprintf(cmd, "%s %s %d", &SHELLROUTE, pdata->ip, pdata->pkgNum);
        fp[pdata->threadnum] = popen(cmd, "r");
        while (fgets(buffer, sizeof(buffer), fp[pdata->threadnum]) != 0)
        {
            strcpy(data[j], buffer);
            memset(buffer, 0, sizeof(buffer));
            j++;
        }
        memset(cmd, 0, sizeof(cmd));
        pclose(fp[pdata->threadnum]);
        root = cJSON_CreateObject();
        cJSON_AddNumberToObject(root, "id", pdata->id);
        cJSON_AddNumberToObject(root, "avg", atoi(data[0]));
        cJSON_AddNumberToObject(root, "mdev", atof(data[1]));
        cJSON_AddNumberToObject(root, "loss", atoi(data[2]));

       	sprintf(cmd, "curl -d '%s' %s/moniter", cJSON_Print(root), serverIp);
        //sprintf(cmd, "echo ' \"%s\" %s/moniter\n' >>/tmp/tmp", cJSON_Print(root), serverIp);
        system(cmd);
        sleep(pdata->cycle);  	
    }
}

//解析配置文件函数
char *parseConfig()
{
    FILE *fp;
    char buffer[512] = {0};
    char pidbuf[16] = {0};
    int fd;
    char *data = NULL;
    int len;   
 
    int pid = getpid();
    if (-1 == (fd = open(PIDFILE, O_CREAT|O_WRONLY|O_TRUNC, 0600)))
    {
        printf("Open file error!\n");
        return NULL;
    }
    sprintf(pidbuf, "%d", pid);
    len = strlen(pidbuf);
    write(fd, pidbuf, len);
    close(fd);
    memset(pidbuf, 0, sizeof(pidbuf));   
    
    fp = fopen(MONITERFILE, "r");
    if (fp == NULL)
        return NULL;
    fgets(buffer, sizeof(buffer), fp);
    buffer[strlen(buffer)] = '\0';
    fclose(fp);
    fp = NULL;
    
    data = malloc(sizeof(buffer) / sizeof(char));
    strcpy(data, buffer);
    
    return data;
}
void threadProcess()
{
    int err, i;
    struct StargetData *this = ptarget;
    for (i = 0; this !=NULL; i++, this = this->next)
    {
        this->threadnum = i;
        err = pthread_create(&ntid[i], NULL, processMoniterData, (void *)this);
    }
    return;
}

void constructTargetStruct(struct StargetData *data)
{
    struct StargetData *current = ptarget;
    if (ptarget == NULL)
    {
        ptarget = data;
        return;
    } else {
        while(current != NULL && current->next !=NULL)
        {
            current = current->next;
        }
        current->next = data;
        return;
    }    
}

//解析配置文件中的json数据
void parseJson(char *data)
{
    cJSON *root, *rootItem, *rule;
    int i, tmpNum, num;
    char *status;
    int ruleSize;
    int errNum = 10;
    
    root = cJSON_Parse(data);
    tmpNum = cJSON_GetArraySize(root);
    targetNum = tmpNum;
    
    char buffer[18];   
    FILE *serverfp = fopen(SERVERFILE, "r");
    fgets(buffer, sizeof(buffer), serverfp);
    buffer[strlen(buffer)] = '\0';
    fclose(serverfp);
    serverIp = malloc(sizeof(char) * 18);
    strcpy(serverIp, buffer);
    
    for (i = 0; i < tmpNum; i++)
    {
        rootItem = cJSON_GetArrayItem(root, i);
        if (rootItem)
        {
            struct StargetData *targetData = malloc(sizeof(struct StargetData));
            targetData->next = NULL;
            
            //判断status,如果是delete则将该节点err设为1，之后不进行探测
            if(cJSON_GetObjectItem(rootItem, "status") != NULL && \
                (strcmp(cJSON_GetObjectItem(rootItem, "status")->valuestring, "delete") == 0))
            {
                targetNum--;
                targetData->err = 1;
            } 
            else 
            {
                targetData->err = 0;
            }
            targetData->id = cJSON_GetObjectItem(rootItem, "id")->valueint;
            targetData->ip = malloc(sizeof(char) * 16);
            strcpy(targetData->ip, (cJSON_GetObjectItem(rootItem, "detectIp")->valuestring));
              
            rule = cJSON_GetObjectItem(rootItem, "ruleWorking");
            if (rule)
            {
                targetData->pkgNum = cJSON_GetObjectItem(rule, "pkgPerTime")->valueint;
                targetData->cycle = cJSON_GetObjectItem(rule, "refreshTimeGap")->valueint;
            }
            
            //err为1，不加入结构体
            if (targetData->err == 1)
            {
                free(targetData->ip);
                free(targetData);   
            } else {
            	constructTargetStruct(targetData);    
	    }
        }
    }    
    //线程处理函数
    threadProcess();
}

// 守护进程初始化函数
void initDaemon()
{
    pid_t pid;
    int i = 0;

    if ((pid = fork()) == -1) {
        printf("Fork error !\n");
        exit(1);
    }
    if (pid != 0) {
        exit(0);        // 父进程退出
    }

    setsid();           // 子进程开启新会话，并成为会话首进程和组长进程
    if ((pid = fork()) == -1) {
        printf("Fork error !\n");
        exit(-1);
    }
    if (pid != 0) {
        exit(0);        // 结束第一子进程，第二子进程不再是会话首进程
    }
    chdir("/tmp");      
    umask(0);           
    for (; i < getdtablesize(); ++i) {
       close(i);        // 关闭打开的文件描述符
    }
    return;
}

int main(int argc, char *argv[])
{
    char buffer[512] = {0};
    
    //初始化 Daemon 进程
    initDaemon();
    
    //解析配置文件
    jsonData = parseConfig();
    if (jsonData == NULL)
    {
	return 1;
    }
    parseJson(jsonData);
    
    //当配置文件修改时发送 USR1 信号，重新加载配置
    int oflags;
    signal(SIGUSR1, restartConfig);
    while(1);
}



