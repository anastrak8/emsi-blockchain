CC = gcc

CFLAGS = -Wall -Wextra -Werror -pedantic
INCLUDES = -I.

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

%.o : %.c
	@echo "Creating object.." 
	${CC} $(FLAGS) -c $< -o $@

libhblk_crypto.a : $(OBJS)
	@echo "Creating libhblk_crypto.a archive.."
	ar r $@ $^

