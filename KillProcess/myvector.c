#include "myvector.h"

#include <stdio.h>

#include <string.h>
#include <stdlib.h>

// 检测是否有足够的容量
static int isallowance(myvector * vect)
{
    printf("进入coming...\n");

    // 如果数组的元素个数/2 == 数组的容量  ->  需要扩容
    if((vect->count << 1) == vect->capacity)
    {
        return 1;
    }
    return 0;
}

// 扩容
static int expansioncapa(myvector * vect)
{
    int newcapacity = vect->capacity << 1;

    char ** numss;

    int count = 100;
    numss = (char **)malloc(sizeof(char*) * count);
    if(numss == NULL)
    {
        perror("malloc init error!");
        return -1;
    }

    for(int i = 0;i<count;i++)
    {
        numss[i] = (char *)malloc(sizeof(char) * 10);
        if(numss[i] == NULL)
        {
            perror("malloc numss[i] error");
            return -1;
        }
        memset(numss[i],0,sizeof(char)*10);
    }

    for(int i = 0;i < count;i++)
    {
        printf("%s\n",numss[i]);
    }

    int size = getcount_vector(vect);
    for(int i = 0;i<size;i++)
    {
        strcpy(numss[i],vect->nums[i]);
    }

    vect->nums = numss;
    vect->capacity = newcapacity;
    return 1;
}

// 初始化动态数组
myvector * init_vector()
{
    myvector * vect = malloc(sizeof(myvector));
    if(vect == NULL)
    {
        perror("malloc error");
        return NULL;
    }

    vect->count = 0;
    vect->capacity = 10;
    //memset(vect.filepath,0,sizeof(vect.filepath));

    vect->nums = (char **)malloc(sizeof(char*) * vect->capacity);
    if(vect->nums == NULL)
    {
        perror("malloc error");
        return NULL;
    }
    

    int i = 0;
    for(;i < vect->capacity;i++)
    {
        vect->nums[i] = (char *)malloc(sizeof(char) * 256);
        if (vect->nums[i] == NULL)
        {
            perror("malloc nums[i] error");
            destory_vector(vect, i);
            return NULL;
        }
        memset(vect->nums[i],0,sizeof(char)* 256);
    }
    return vect;
}

// 销毁myvector
int destory_vector(myvector * vect,int index)
{
    for(int i = 0;i < index;i++)
    {
        {
            free(vect->nums[i]);
            vect->nums[i] = NULL;
        }
    }

    if(vect->nums != NULL)
    {
        free(vect->nums);
        vect->nums = NULL;
    }

    if(vect)
    {
        free(vect);
        vect = NULL;
    }
}

// 向数组中添加元素
int push_vector(myvector * vect,const char * str)
{
    if(str == NULL)
    {
        return -1;
    }
    
    if(vect->count == vect->capacity - 2)
    {
        expansioncapa(vect);
    }
    
    
    strcpy(vect->nums[vect->count++],str);

    return 1;
}


// 获取数组元素
char * pop_vector(myvector * vect,int index)
{
    return vect->nums[index];
}

// 获取数组的数量
int getcount_vector(myvector * vect)
{
    return vect->count;
}

// 获取数组的容量
int getcapacity_vector(myvector * vect)
{
    return vect->capacity;
}

// 检测容器是否寻找进程
int ischeckpid(myvector * vect,const char * str)
{
    for(int i = 0;i < vect->count;i++)
    {
        if((strcmp(vect->nums[i],str) == 0))
        {
            return 1;
        }
    }
    return 0;
}




