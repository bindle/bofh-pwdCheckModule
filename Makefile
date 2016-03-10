
CFLAGS			= -W -Wall -Werror

all: lib/pwdCheckModule-poc.so

lib/pwdCheckModule-poc.o: lib/pwdCheckModule-poc.c Makefile
	$(CC) $(CFLAGS) -c -fPIC -o $(@) lib/pwdCheckModule-poc.c

lib/pwdCheckModule-poc.so: lib/pwdCheckModule-poc.o
	$(CC) -shared -o $(@) lib/pwdCheckModule-poc.o

clean:
	rm -f lib/*.so lib/*.o
