#ifndef __PROCESS_H__
#define __PROCESS_H__

// 自己的动态数组
#include "myvector.h"

// 生成md5的序列
/*
    para1:将路径作为输入参数
    para2:输出到output中
    返回值:成功返回1,失败返回-1
*/
int get_md5(const char * input, char * output);

// 将进程字段进行解析出进程路径
const char * parse_fields(const char * str);

// 输入进程路径和文件的MD5，快速定位到当前系统是否存在该进程
/*
    parameter1:进程路径
    parameter2:文件对应的MD5
*/
int kill_process(const char * process_path,const char * process_md5);

// 检查是否是进程号
/*
    parameter1:子目录
    返回值:成功返回0，失败返回-1
*/
int check_pid(const char * str);

// 判断路径是否是绝对路径
// 返回值:是绝对路径返回1，不是绝对路径返回0
int isabsolutepath(const char * str);

// 判断文件是否存在
// 返回值:文件存在返回1，文件不存在返回0
int isfileexist(const char * str);

// 杀指定的进程号
int killappointpid(myvector * vect,const char * filepath);


// 检测是否是僵尸进程
int isdeadpid(const char * str);

// 处理僵尸进程
char * dealdeadpid(char * str_pid);


#endif //__PROCESS_H__