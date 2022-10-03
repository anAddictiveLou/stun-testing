.PHONY: all clean

all: 
	gcc -o second_stun_client stun_client.c stun.c -I. -g
	gcc -o first_stun_client stun_client.c stun.c -I. -g
clean: 
	rm stun_client