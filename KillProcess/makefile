OBJ=$(patsubst %.c, %.o, $(wildcard ./*.c))
TARGET=test_main

LDFALGS=-L./src_so -L./src_so2
LIBS=-lVirus -lcrypto -lssl

$(TARGET):$(OBJ)
	$(CC) $^ $(LIBS) $(LDFALGS) -o $@  

#模式匹配
%.o:%.c
	$(CC) -c $^ -o $@

clean:
	$(RM) *.o $(TARGET)