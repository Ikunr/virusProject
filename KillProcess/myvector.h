#ifndef __MYVECTOR_H__
#define __MYVECTOR_H__

typedef struct myvector
{
    char ** nums;

    // 数组的元素数量
    int count;
    // 数组的容量
    int capacity;
}myvector;

// 初始化动态数组
myvector * init_vector();

// 向数组中添加元素
int push_vector(myvector * vect,const char * str);

// 获取数组的数量
int getcount_vector(myvector * vect);

// 获取数组的容量
int getcapacity_vector(myvector * vect);

// 销毁myvector
int destory_vector(myvector * vect,int index);

// 获取数组元素
char * pop_vector(myvector * vect,int index);

// 检测容器是否寻找进程
int ischeckpid(myvector * vect,const char * str);


#endif //__MYVECTOR_H__