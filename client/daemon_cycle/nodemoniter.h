#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>

struct StargetData{
	int id;
	char *ip;
	int pkgNum;
	int cycle;
	int err;
	int threadnum;
	struct StargetData *next;
};
