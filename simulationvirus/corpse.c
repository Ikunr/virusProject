#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

int main(int argc,const char * argv[])
{
    pid_t pid = fork();
    if(pid < 0)
    {
        perror("fork error!");
        return -1;
    }
    
    // 父进程
    if(pid)
    {
        printf("我是父进程:%d\n",getpid());
        while(1);
    }   
    else if(pid == 0)
    {
        printf("我是子进程:%d\n",getpid());
        sleep(3);
        exit(EXIT_SUCCESS);
    }
    printf("111\n");


    return 0;
}