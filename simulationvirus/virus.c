#include <stdio.h>
#include <unistd.h>


// 病毒程序
int main(int argc,const char * argv[])
{
    int count = 1;
    while(count <= 1000)
    {
        // printf("hello ");
        // printf("%d\n",count++);
        sleep(1);
    }

    return 0;
}