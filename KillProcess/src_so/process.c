#include "process.h"

#include <stdio.h>
#include <dirent.h>
#include <openssl/md5.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/evp.h>

// 检查是否是进程号
/*
    parameter1:子目录
    返回值:成功返回0，失败返回-1
*/
int check_pid(const char * str)
{
    const char * ptr = str;
    while(*ptr != '\0')
    {
        if(*ptr >= '0' && *ptr <= '9')
        {
            ptr++;
            continue;
        }
        else // 非数字，不是进程号
        {
            return 0;
        }
        ptr++;
    }
    return 1;
}

// 生成md5的序列
/*
    para1:将路径作为输入参数
    para2:输出到output中
    返回值:成功返回1,失败返回-1
*/
int get_md5(const char * input, char * output)
{
    /* 打开外部传来的路径 */
    int fd = open(input, O_RDONLY);
    if(fd == -1)
    {
        printf("input %s error\n",input);
        return -1;
    }
    
    /* 定义缓冲区大小 */
    unsigned char buf[1024];
    memset(buf,0,sizeof(buf));

    /* 定义MD5的计算结果 */
    unsigned char md[16];
    memset(md, 0, sizeof(md));

    /* 存储MD5字符串的数组 */
    char md5_str[33];
    memset(md5_str, 0, sizeof(md5_str));

    /* 定义MD5 并进行初始化 */
    MD5_CTX ctx;
    MD5_Init(&ctx);
    

    /* 循环读文件内容并更新MD5的值 */
    while(1)
    {
        int size = read(fd, buf, sizeof(buf));
        /* 更新MD5的值 */
        MD5_Update(&ctx, buf, size);
        if(size == 0 || size < 1024)
        {
            break;
        }
    }
    close(fd);

    /* MD5的最终值计算 */
    MD5_Final(md, &ctx);

   
    int jdx = 0;
    for(int idx = 0; idx < 16; idx++)
    {
        /* 将每个字符串的十六进制添加到MD5字符串中 */
        sprintf(md5_str + jdx, "%02x", md[idx]);
        jdx += 2;
    }
    /* 将MD5字符串复制到输出参数 */
    strcpy(output, md5_str);
    return 0;
}

// 输入进程路径和文件的MD5，快速定位到当前系统是否存在该进程
/*
    parameter1:进程路径
    parameter2:文件对应的MD5
*/
int kill_process(const char * process_path, const char * process_md5)
{
    // 打开/proc文件夹 /proc文件 该目录包含有关系统中运行的进程信息 
    DIR * dir_ptr = opendir("/proc");
    if(dir_ptr == NULL)
    {
        perror("can not open /proc\n");
        return -1;
    }
    else
    {
        FILE * fp = NULL;
        /* 初始化动态数组 */
        myvector * vect = init_vector();

        
        char filepath[128];
        char command[128];
        char buf[256];

        char md5buf[33] = {0};

        /* md5比对成功标志位 */
        int flag = 0;

        /* 需要杀死的进程个数 */
        int count = 0;
        
        char * fatherpid = NULL;

        char * fatherppid = NULL;
    

        struct dirent * dir = NULL;
        while((dir = readdir(dir_ptr)) != NULL)
        {
            memset(filepath, 0, sizeof(filepath));
            memset(command, 0, sizeof(command));
            memset(buf, 0, sizeof(buf)); 
            memset(md5buf, 0, sizeof(md5buf));
            
            /* 找到进程号的文件夹 dir->d_type == 4 判断是否是目录文件 
            check_pid 判断是否为进程号 */
            if(check_pid(dir->d_name) && dir->d_type == 4)
            {
                /* /proc/filename/exe*/
                strcpy(filepath, "/proc/");
                strcat(filepath, dir->d_name);
                strcat(filepath, "/exe");

                /* ls -l /proc/filename/exe  */ 
                strcpy(command, "ls -l ");
                strcat(command, filepath);

                /* 执行一个命令 并将结果保存到文件指针fp中 */
                fp = popen(command, "r");
                if(fp == NULL)
                {
                    perror("command error\n");
                    return -1;
                }
                /* 获取执行命令的结果字符串 */
                fgets(buf, sizeof(buf), fp);
                pclose(fp);

                /* 如果不包含 > 链接符号== 0  说明可能是僵尸进程 */
                if(isdeadpid(buf) == 0) 
                {
                    /*  处理僵尸进程 如果为空说明不是僵尸进程 */
                    fatherpid = dealdeadpid(dir->d_name);
                    if(fatherpid != NULL)
                    {
                        /* 不为空 */
                        // 父进程在我的容器中
                        if(ischeckpid(vect, fatherppid) == 0)
                        {
                            printf("僵尸进程杀不掉！\n");
                        }
                    }
                    
                }

                /* 将字段解析获取路径 
                例如 lrwxrwxrwx 1 root root 0 Feb 29 11:45 /proc/1/exe -> /usr/lib/systemd/systemd 
                这个函数 parse_fields 只获取路径 /usr/lib/systemd/systemd 
                */
                const char * result = parse_fields(buf);

                /* 如果和传进来的路径相同 */
                if((strncmp(process_path, result, strlen(process_path))) == 0)
                {
                    count++;
                    /* 进行MD5的判断 md5buf传出参数 已经是十六进制了 */
                    get_md5(process_path, md5buf);
                    
                    // 进行md5序列的比对
                    if(strcmp(md5buf, process_md5) != 0)
                    {
                        printf("MD5序列比对不成功!");
                    }
                    else // md5值相同
                    {
                        /* 将进程号添加到动态数组中 */
                        push_vector(vect, dir->d_name);
                    }
                }
                
            }
        } //end while
        closedir(dir_ptr);

        for(int idx = 0; idx < count; idx++)
        {
            printf("pid:%s\n", pop_vector(vect, idx));
        }

        // 杀指定的进程号
        killappointpid(vect, process_path);
    }
}


// 判断路径是否是绝对路径
// 返回值:是绝对路径返回1，不是绝对路径返回0
int isabsolutepath(const char * str)
{
    const char * ptr = str;
    
    int flag = 0;
    while(*ptr != '\0')
    {
        if(*ptr == '/')
        {
            flag = 1;
        }
        ptr++;
    }
    return flag == 1 ? 1 : 0;
}

// 判断文件是否存在
// 返回值:文件存在返回1，文件不存在返回0
int isfileexist(const char * str)
{
    int fd = open(str, O_RDONLY);
    if(fd == -1)
    {
        return 0;
    }
    close(fd);

    return 1;
}

// 将进程字段进行解析出进程路径
const char * parse_fields(const char * str)
{
    const char * ptr = str;
    const char * pos = NULL;
    while(*ptr != '\0')
    {
        if(*ptr == ' ')
        {
            pos = ptr;
        }
        ptr++;
    }
    return pos+1;
}

/* 杀指定的进程号 */
int killappointpid(myvector * vect, const char * filepath)
{
    FILE * fp = NULL;

    /* 获取动态数组的数量 */
    int size = getcount_vector(vect);
    char command[64];
    memset(command, 0, sizeof(command));
    strcpy(command, "chmod -x ");
    strcat(command, filepath);

    /* 到这的命令 chmod -x fileName */
    fp = popen(command, "r");
    if(fp == NULL)
    {
        perror("popen error");
        return -1;
    }
    pclose(fp);

    char buf[1024] = {0};
    for(int idx = 0; idx < size; idx++)
    {
        /* atoi字符串转整形 将动态数组进程号拿出 */
        int pidnumber = atoi(pop_vector(vect, idx));
        printf("pidnumber:%d\n", pidnumber); 
        /* 发9号信号 杀死进程 */
        kill(pidnumber, SIGKILL);
    }
    
    // 销毁容器
    destory_vector(vect,vect->capacity);
}



// 检测是否是僵尸进程
int isdeadpid(const char * str)
{
    const char * ptr = str;
    while(*ptr != '\0')
    {
        if(*ptr == '>')
        {
            return 1;
        }
        ptr++;
    }
    return 0;
}

// 处理僵尸进程
char * dealdeadpid(char * str_pid)
{
    char md[128];

    memset(md,0,sizeof(md));
    
    /* 查看进程的状态是否为僵尸 和查看父进程pid */
    snprintf(md, sizeof(md), "grep -E \"State|PPid\" /proc/%s/status", str_pid);

    int flag = 0;
    FILE * fp = popen(md, "r");
    char * pos = NULL;

    char buf[1024] = {0};

    while(fgets(buf,sizeof(buf),fp))
    {
        if(flag == 1)
        {
            /* 找到包含PPid的 */
            pos = strstr(buf, "PPid");
            if(pos == NULL)
            {
                perror("strstr PPid error");
                return NULL;
            }
            /* 进程号+6 */
            pos += 6;
            /* 找到末尾的位置 用 '\0' 替换 '\n' */
            char * n_ptr = strrchr(pos, '\n');
            if (n_ptr != NULL)
            {
                *n_ptr = '\0';
            }
            return pos;
        }
        /* 从buf中查找第一次出现Z的位置 */
        if (strchr(buf, 'Z') || strchr(buf,'z'))
        {
            flag = 1;
        }
    }
    return pos;
}
