OBJECT = main.o parse.o tools.o
NAME = sniffer

CC		=	gcc -o
CFLAGS	=	-W -Wall

$(NAME) : $(OBJECT)
		$(CC) $(NAME) $(CFLAGS) $(OBJECT)

main.o  : common.h tools.h parse.h
parse.o : parse.h tools.h
tools.o : tools.h

.PHONY  : run clean

clean	:	
		rm -f $(NAME) $(OBJECT)