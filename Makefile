CFLAGS  := -g -ggdb -O0 -Wall -Wextra -Werror
LDFLAGS := -levent -lcrypto 

SRC     := $(wildcard *.c)
OBJ     := $(SRC:.c=.o)
EXE     := grp-proxy



.PHONY: all
all: $(EXE)

$(OBJ): %.o: %.c
	gcc $(CFLAGS) -o $*.o -c $<

$(EXE): $(OBJ)
	gcc -o $(EXE) $(OBJ) $(LDFLAGS)

include $(OBJ:.o=.d)

%.d: %.c
	./build/depend.sh `dirname $*.c` $(CFLAGS) $*.c > $@

.PHONY: clean
clean:
	rm -rf $(OBJ) $(EXE)

