#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdbool.h>
#include <fcntl.h>
#include "stun.h"

int main(int argc, char *argv[])
{
    if (argc != 4) {
		printf("\nusage: ./stun_client <server_ip> <server_port> <local_port>\n");
		exit(EXIT_FAILURE);
	} 
	start(argv);
	return 0;
}
