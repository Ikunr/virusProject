#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

// 守护进程
int main(int argc,const char * argv[])
{
    pid_t pid = fork();
    if(pid < 0)
    {
        perror("fork error");
        return -1;
    }    
    if(pid)
    {
        exit(0);
    }

    if(setsid() == -1)
    {
        printf("setsid error\n");
        exit(1);
    }

    char command[64];
    memset(command,0,sizeof(command));
    // 病毒程序
    strcpy(command,"./");
    strcat(command,argv[1]);    // argv[1]就是病毒程序
    FILE * fp = NULL;
    char buf[256] = {0};
    int flag = 1;
    while(1)
    {
        if (flag)
        {
            flag = 0;
            fp = popen(command,"r");
            while(fgets(buf, 256, fp))
            {
                flag = 1;
            }
            pclose(fp);
        }
    }
   
}
   