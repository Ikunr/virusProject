# test_main: main.c process.c myvector.c 
# 	gcc -g $^ -o $@ -lcrypto -lssl
	
OBJ=$(patsubst %.c, %.o, $(wildcard ./*.c))
TARGET=libVirus.so


$(TARGET):$(OBJ)
	$(CC) -shared -fPIC $^ -o $@
# 发布
	sudo cp $(TARGET) /usr/local/lib/

#模式匹配
%.o:%.c
	$(CC) -c $^ -o $@

clean:
	$(RM) *.o $(TARGET) libVirus.so
	sudo $(RM) /usr/local/lib/libVirus.so