#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "process.h"



int main(int argc,const char * argv[])
{
    // 命令行参数的个数
    if(argc != 3)
    {
        perror("命令行参数输入有误!");
        return -1;
    }
    printf("命令行参数:%d\n",argc);

    struct timeval begintime, endtime;
    gettimeofday(&begintime, NULL);
    
#if 0
    // 判断进程路径是否是绝对路径
    int ret = isabsolutepath(argv[1]);
    if(ret == 0)    // 不是绝对路径
    {   
        perror("输入路径需要绝对路径");
        return -1;
    }

    // 判断进程是否存在
    ret = isfileexist(argv[1]);
    if(ret == 0)
    {
        perror("进程绝对路径有误!\n");
        return -1;
    }
#endif

    // 命令行参数1和命令行参数2
    kill_process(argv[1], argv[2]);

    gettimeofday(&endtime, NULL);
    printf("所用时间:%ldms\n",(endtime.tv_sec - begintime.tv_sec) * 1000 + (endtime.tv_usec - begintime.tv_usec));

    return 0;
}