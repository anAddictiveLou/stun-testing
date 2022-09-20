.PHONY: all clean

all: 
	gcc -o first_stun_client stun_client.c stun.c -I. -g
	gcc -o second_stun_client stun_client.c stun2.c -I. -g
clean: 
	rm stun_client