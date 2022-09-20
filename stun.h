#define MAX_SIZE_BUF 300
#define STUN_HDR_LEN 20 
#define STUN_ATTR_HDR_LEN 4
#define STUN_BINDING_METHOD 0X0001
#define STUN_RESPONE_SUCCESS 0x0101
#define XOR_MAPPED_ADDR_ATTR 0x0020
#define MAGIC_COOKIE 0x2112A442
#define LOCAL_ADDR_LEN 50
#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

struct stun_msg_hdr
{
    uint16_t method;
	uint16_t len;
	uint32_t magic_cookie;
    uint8_t tsx_id[12];
};

struct stun_attr_hdr
{
    uint16_t type;
    uint16_t length;
};


int stun_implement(int sockfd, struct sockaddr_in servaddr, char * return_ip, unsigned short * return_port);
void start(char **argv);
char* get_localaddr(char* info, int n);
void communicate(int sockfd);
int guard(int n, char * err);
