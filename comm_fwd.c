#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <termios.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/util.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#define MAX_MTU 9000

const char *default_master = "/dev/ttyAMA0";
const int default_baudrate = 115200;
const char *default_out_addr = "127.0.0.1:14600";
const char *default_2_out_addr = "127.0.0.1:14700";
const char *default_in_addr = "127.0.0.1:14601";

struct bufferevent *serial_bev;
struct sockaddr_in sin_out = {
	.sin_family = AF_INET,
};
struct sockaddr_in sin_2_out = {
	.sin_family = AF_INET,
};

int out_sock;
int out_2_sock;



#if 0

#define PACKET_HEADER             	0x73

// ROV_BOARD_STATE_RESPONCE   	0x21
uint32_t board_packet_rov_board_state_responce(uint8_t * u8_input_buf)
{
	BoardRovState *pBoardState;
	uint32_t u32_packet_size = 0;
	uint16_t u16_CRC_calculated = 0;

    // Get pointer to current board state:
	board_data_get_rov_state(&pBoardState);

	u8_input_buf[0] = PACKET_HEADER;
	u8_input_buf[1] = 0x24;						// Length of data 0x24=36
	u8_input_buf[2] = ROV_BOARD_STATE_RESPONCE; // Command
	u8_input_buf[3] = (pBoardState->u16_boardBatteryVoltage >> 0) & 0xFF;
	u8_input_buf[4] = (pBoardState->u16_boardBatteryVoltage >> 8) & 0xFF;

	u8_input_buf[5] = (pBoardState->u16_boardConsumptionCurrent >> 0) & 0xFF;
	u8_input_buf[6] = (pBoardState->u16_boardConsumptionCurrent >> 8) & 0xFF;

	u8_input_buf[7]  = (((uint16_t)pBoardState->i3d_rawGyro.i16_X) >> 0) & 0xFF;
	u8_input_buf[8]  = (((uint16_t)pBoardState->i3d_rawGyro.i16_X) >> 8) & 0xFF;
	u8_input_buf[9]  = (((uint16_t)pBoardState->i3d_rawGyro.i16_Y) >> 0) & 0xFF;
	u8_input_buf[10] = (((uint16_t)pBoardState->i3d_rawGyro.i16_Y) >> 8) & 0xFF;
	u8_input_buf[11] = (((uint16_t)pBoardState->i3d_rawGyro.i16_Z) >> 0) & 0xFF;
	u8_input_buf[12] = (((uint16_t)pBoardState->i3d_rawGyro.i16_Z) >> 8) & 0xFF;

	u8_input_buf[13] = (((uint16_t)pBoardState->i3d_rawAccelerometer.i16_X) >> 0) & 0xFF;
	u8_input_buf[14] = (((uint16_t)pBoardState->i3d_rawAccelerometer.i16_X) >> 8) & 0xFF;
	u8_input_buf[15] = (((uint16_t)pBoardState->i3d_rawAccelerometer.i16_Y) >> 0) & 0xFF;
	u8_input_buf[16] = (((uint16_t)pBoardState->i3d_rawAccelerometer.i16_Y) >> 8) & 0xFF;
	u8_input_buf[17] = (((uint16_t)pBoardState->i3d_rawAccelerometer.i16_Z) >> 0) & 0xFF;
	u8_input_buf[18] = (((uint16_t)pBoardState->i3d_rawAccelerometer.i16_Z) >> 8) & 0xFF;

	u8_input_buf[19] = (((uint16_t)pBoardState->i3d_rawMagnitometer.i16_X) >> 0) & 0xFF;
	u8_input_buf[20] = (((uint16_t)pBoardState->i3d_rawMagnitometer.i16_X) >> 8) & 0xFF;
	u8_input_buf[21] = (((uint16_t)pBoardState->i3d_rawMagnitometer.i16_Y) >> 0) & 0xFF;
	u8_input_buf[22] = (((uint16_t)pBoardState->i3d_rawMagnitometer.i16_Y) >> 8) & 0xFF;
	u8_input_buf[23] = (((uint16_t)pBoardState->i3d_rawMagnitometer.i16_Z) >> 0) & 0xFF;
	u8_input_buf[24] = (((uint16_t)pBoardState->i3d_rawMagnitometer.i16_Z) >> 8) & 0xFF;

	u8_input_buf[25] = (pBoardState->u32_boardInternalBaro >> 0)  & 0xFF;
	u8_input_buf[26] = (pBoardState->u32_boardInternalBaro >> 8)  & 0xFF;
	u8_input_buf[27] = (pBoardState->u32_boardInternalBaro >> 16) & 0xFF;
	u8_input_buf[28] = (pBoardState->u32_boardInternalBaro >> 24) & 0xFF;

	u8_input_buf[29] = (pBoardState->u16_boardInternalTemperature >> 0) & 0xFF;
	u8_input_buf[30] = (pBoardState->u16_boardInternalTemperature >> 8) & 0xFF;

	u8_input_buf[31] = (pBoardState->u32_boardExternalBaro >> 0)  & 0xFF;
	u8_input_buf[32] = (pBoardState->u32_boardExternalBaro >> 8)  & 0xFF;
	u8_input_buf[33] = (pBoardState->u32_boardExternalBaro >> 16) & 0xFF;
	u8_input_buf[34] = (pBoardState->u32_boardExternalBaro >> 24) & 0xFF;

	u8_input_buf[35] = (pBoardState->u16_boardExternalTemperature >> 0) & 0xFF;
	u8_input_buf[36] = (pBoardState->u16_boardExternalTemperature >> 8) & 0xFF;

	u8_input_buf[37] = pBoardState->u8_boardLightLedOnOff;

	board_packet_crc_calculation(u8_input_buf, &u16_CRC_calculated);
	u8_input_buf[38] = u16_CRC_calculated & 0xFF;
	u32_packet_size = u8_input_buf[1]+3;
	return(u32_packet_size);
}

void board_packet_crc_calculation(uint8_t * pu8_data, uint16_t *pu16_crc)
{
	uint16_t u16_crc = 0;
	uint16_t u16_counter = 0;
	uint16_t u16_size = pu8_data[1];

	while(u16_counter < u16_size)
	{
		u16_crc = u16_crc + pu8_data[u16_counter + 2];
		u16_counter++;
	}

	*pu16_crc = u16_crc;
}
#endif









static void print_usage()
{
	printf("Usage: mavfwd [OPTIONS]\n"
	       "Where:\n"
	       "  --master        Local MAVLink master port (%s by default)\n"
	       "  --baudrate      Serial port baudrate (%d by default)\n"
	       "  --out           Remote output port (%s by default)\n"
	       "  --in            Remote input port (%s by default)\n"
	       "  --help          Display this help\n",
	       default_master, default_baudrate, default_out_addr,
	       default_in_addr);
}

static speed_t speed_by_value(int baudrate)
{
	switch (baudrate) {
	case 9600:
		return B9600;
	case 19200:
		return B19200;
	case 38400:
		return B38400;
	case 57600:
		return B57600;
	case 115200:
		return B115200;
	case 230400:
		return B230400;
	case 460800:
		return B460800;
	case 500000:
		return B500000;
	case 921600:
		return B921600;
	case 1500000:
		return B1500000;
	default:
		printf("Not implemented baudrate %d\n", baudrate);
		exit(EXIT_FAILURE);
	}
}

static bool parse_host_port(const char *s, struct in_addr *out_addr,
			    in_port_t *out_port)
{
	char host_and_port[32] = { 0 };
	strncpy(host_and_port, s, sizeof(host_and_port) - 1);

	char *colon = strchr(host_and_port, ':');
	if (NULL == colon) {
		return -1;
	}

	*colon = '\0';
	const char *host = host_and_port, *port_ptr = colon + 1;

	const bool is_valid_addr = inet_aton(host, out_addr) != 0;
	if (!is_valid_addr) {
		printf("Cannot parse host `%s'.\n", host);
		return false;
	}

	int port;
	if (sscanf(port_ptr, "%d", &port) != 1) {
		printf("Cannot parse port `%s'.\n", port_ptr);
		return false;
	}
	*out_port = htons(port);

	return true;
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
	struct event_base *base = arg;
	(void)event;

	printf("%s signal received\n", strsignal(fd));
	event_base_loopbreak(base);
}

static void dump_mavlink_packet(unsigned char *data, const char *direction)
{
	uint8_t seq = data[2];
	uint8_t sys_id = data[3];
	uint8_t comp_id = data[4];
	uint8_t msg_id = data[5];

	printf("%s sender %d/%d\t%d\t%d\n", direction, sys_id, comp_id, seq,
	       msg_id);
	
}

/* https://discuss.ardupilot.org/uploads/short-url/vS0JJd3BQfN9uF4DkY7bAeb6Svd.pdf
 * 0. Message header, always 0xFE
 * 1. Message length
 * 2. Sequence number -- rolls around from 255 to 0 (0x4e, previous was 0x4d)
 * 3. System ID - what system is sending this message
 * 4. Component ID- what component of the system is sending the message
 * 5. Message ID (e.g. 0 = heartbeat and many more! Don’t be shy, you can add too..)
 */
static bool get_mavlink_packet(unsigned char *in_buffer, int buf_len,
			       int *packet_len)
{
	if (buf_len < 6 /* header */) {
		return false;
	}
	assert(in_buffer[0] == 0xFE);

	uint8_t msg_len = in_buffer[1];
	*packet_len = 6 /* header */ + msg_len + 2 /* crc */;
	if (buf_len < *packet_len)
		return false;

	dump_mavlink_packet(in_buffer, ">>");

	return true;
}

// Returns num bytes before first occurrence of 0xFE or full data length
static size_t until_first_fe(unsigned char *data, size_t len)
{
	for (size_t i = 1; i < len; i++) {
		if (data[i] == 0xFE) {
			return i;
		}
	}
	return len;
}

static void serial_read_cb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	int packet_len, in_len;
	struct event_base *base = arg;

	while ((in_len = evbuffer_get_length(input))) 
	{
		unsigned char *data = evbuffer_pullup(input, in_len);
		if (data == NULL) 
		{
			return;
		}

		// find first 0xFE and skip everything before it
		if (*data != 0xFE) 
		{
		    int bad_len = until_first_fe(data, in_len);
  		    printf(">> Skipping %d bytes of unknown data\n", bad_len);
		    evbuffer_drain(input, bad_len);
		    continue;
		}

		if (!get_mavlink_packet(data, in_len, &packet_len))
		{
		    return;
		}
		// TODO: check CRC correctness and skip bad packets

		if(sendto(out_sock,data,packet_len,0,(struct sockaddr *)&sin_out,sizeof(sin_out)) == -1) 
		{
			perror("sendto()");
			event_base_loopbreak(base);
		}

		evbuffer_drain(input, packet_len);
	}
}

static void serial_event_cb(struct bufferevent *bev, short events, void *arg)
{
	(void)bev;
	struct event_base *base = arg;

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		printf("Serial connection closed\n");
		event_base_loopbreak(base);
	}
}

static void in_read(evutil_socket_t sock, short event, void *arg)
{
	(void)event;
	unsigned char buf[MAX_MTU];
	struct event_base *base = arg;
	ssize_t nread;

	nread = recvfrom(sock, &buf, sizeof(buf) - 1, 0, NULL, NULL);
	if (nread == -1) {
		perror("recvfrom()");
		event_base_loopbreak(base);
	}

	assert(nread > 6);

	dump_mavlink_packet(buf, "<<");

	bufferevent_write(serial_bev, buf, nread);
}

static int handle_data(
                        const char *port_name, 
                        int baudrate,
		        const char *out_addr, 
		        const char *out_2_addr,
		        const char *in_addr
		      )
{
	struct event_base *base = NULL;
	struct event *sig_int = NULL, *in_ev = NULL;
	int ret = EXIT_SUCCESS;

	int serial_fd = open(port_name, O_RDWR | O_NOCTTY);
	if (serial_fd < 0) {
		printf("Error while openning port %s: %s\n", port_name,
		       strerror(errno));
		return EXIT_FAILURE;
	};
	evutil_make_socket_nonblocking(serial_fd);

	struct termios options;
	tcgetattr(serial_fd, &options);
	cfsetspeed(&options, speed_by_value(baudrate));

	options.c_cflag &= ~CSIZE; // Mask the character size bits
	options.c_cflag |= CS8; // 8 bit data
	options.c_cflag &= ~PARENB; // set parity to no
	options.c_cflag &= ~PARODD; // set parity to no
	options.c_cflag &= ~CSTOPB; // set one stop bit

	options.c_cflag |= (CLOCAL | CREAD);

	options.c_oflag &= ~OPOST;

	options.c_lflag &= 0;
	options.c_iflag &= 0; // disable software flow controll
	options.c_oflag &= 0;

	cfmakeraw(&options);
	tcsetattr(serial_fd, TCSANOW, &options);

	out_sock = socket(AF_INET, SOCK_DGRAM, 0);
	int in_sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sin_in = {
		.sin_family = AF_INET,
	};
	if (!parse_host_port(in_addr, (struct in_addr *)&sin_in.sin_addr.s_addr,
			     &sin_in.sin_port))
		goto err;
	if (!parse_host_port(out_addr,
			     (struct in_addr *)&sin_out.sin_addr.s_addr,
			     &sin_out.sin_port))
		goto err;
	if (!parse_host_port(out_2_addr,
			     (struct in_addr *)&sin_2_out.sin_addr.s_addr,
			     &sin_2_out.sin_port))
		goto err;

	if (bind(in_sock, (struct sockaddr *)&sin_in, sizeof(sin_in))) {
		perror("bind()");
		exit(EXIT_FAILURE);
	}
	printf("Listening on %s...\n", in_addr);

	base = event_base_new();

	sig_int = evsignal_new(base, SIGINT, signal_cb, base);
	event_add(sig_int, NULL);
	// it's recommended by libevent authors to ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	serial_bev = bufferevent_socket_new(base, serial_fd, 0);
	bufferevent_setcb(serial_bev, serial_read_cb, NULL, serial_event_cb,
			  base);
	bufferevent_enable(serial_bev, EV_READ);

	in_ev = event_new(base, in_sock, EV_READ | EV_PERSIST, in_read, NULL);
	event_add(in_ev, NULL);

	event_base_dispatch(base);

err:
	if (serial_fd >= 0)
		close(serial_fd);

	if (serial_bev)
		bufferevent_free(serial_bev);

	if (in_ev) {
		event_del(in_ev);
		event_free(in_ev);
	}

	if (sig_int)
		event_free(sig_int);

	if (base)
		event_base_free(base);

	libevent_global_shutdown();

	return ret;
}

int main(int argc, char **argv)
{
	const struct option long_options[] = {
		{ "master", required_argument, NULL, 'm' },
		{ "baudrate", required_argument, NULL, 'b' },
		{ "out", required_argument, NULL, 'o' },
		{ "out2", required_argument, NULL, 'u' },
		{ "in", required_argument, NULL, 'i' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	const char *port_name = default_master;
	int baudrate = default_baudrate;
	const char *out_addr = default_out_addr;
	const char *out_2_addr = default_2_out_addr;
	
	const char *in_addr = default_in_addr;

	int opt;
	int long_index = 0;
	while ((opt = getopt_long_only(argc, argv, "", long_options, &long_index)) != -1) 
	{
		switch (opt) 
		{
		    case 'm':
			port_name = optarg;
			break;
		    case 'b':
			baudrate = atoi(optarg);
			break;
		    case 'o':
			out_addr = optarg;
			break;
		    case 'u':
			out_2_addr = optarg;
			break;
				
		    case 'i':
			in_addr = optarg;
			break;
		    case 'h':
		    default:
			print_usage();
			return EXIT_SUCCESS;
		}
	}
	return handle_data(port_name, baudrate, out_addr,out_2_addr, in_addr);
}
