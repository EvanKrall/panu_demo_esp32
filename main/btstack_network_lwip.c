#define BTSTACK_FILE__ "btstack_network_lwip.c"


#include "btstack_network.h"
#include "btstack_config.h"
#include <stdlib.h>
#include <string.h>


// #include "lwip/err.h"
#include "lwip/init.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"

#include "dhcpserver/dhcpserver.h"

static struct netif lwip_netif;
static struct ip4_addr ipaddr;
static struct ip4_addr netmask;
static struct ip4_addr gw;

static void (*btstack_network_send_packet_callback)(const uint8_t * packet, uint16_t size);


err_t myif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);

err_t myif_init(struct netif *netif) {
	lwip_init();
	printf("myif_init\n");
	lwip_netif.output = myif_output;
	return 0;
}

err_t myif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
	printf("myif_output\n");
	struct pbuf *q;
	uint16_t size = p->tot_len;
	uint8_t packet[size];
	uint16_t i = 0;

	for (q = p; q != NULL; q = q->next) {
		memcpy(packet + i, q->payload, q->len);
		i += q->len;
	}
	// assert that i == size

	btstack_network_send_packet_callback(packet, size);

	return 0;
}

/**
 * @brief Initialize network interface
 * @param send_packet_callback
 */
void btstack_network_init(void (*send_packet_callback)(const uint8_t * packet, uint16_t size)) {
	printf("btstack_network_init\n");
	btstack_network_send_packet_callback = send_packet_callback;

	IP4_ADDR(&ipaddr,  169, 254,   1,   1);
	IP4_ADDR(&netmask, 255, 255,   0,   0);
	IP4_ADDR(&gw,        0,   0,   0,   0);
	netif_add(
		&lwip_netif,
		&ipaddr,
		&netmask,
		// IP4_ADDR(255, 255,   0,   0};
		&gw,
		// IP4_ADDR(  0,   0,   0,   0};
		NULL,
		&myif_init,
		tcpip_input
	);

	dhcps_start(&lwip_netif, ipaddr);
}

/**
 * @brief Bring up network interfacd
 * @param network_address
 * @return 0 if ok
 */
int  btstack_network_up(bd_addr_t network_address) {
	return 0;
}

/**
 * @brief Shut down network interfacd
 * @param network_address
 * @return 0 if ok
 */
int  btstack_network_down(void) {
	return 0;
}

/** 
 * @brief Receive packet on network interface, e.g., forward packet to TCP/IP stack 
 * @param packet
 * @param size
 */
void btstack_network_process_packet(const uint8_t * packet, uint16_t size) {
	printf("btstack_network_process_packet\n");
	struct pbuf *p, *q;
	uint16_t i = 0;

	p = pbuf_alloc(PBUF_IP, size, PBUF_RAM);
	printf("p = %x\n", p);
	if (p != NULL) {
		for (q = p; q != NULL; q = q->next) {
			printf("q = %x\n", q);
			memcpy(q->payload, packet + i, q->len);
			printf("q->len = %d\n", q->len);
			i += q->len;
		}
		err_t err = lwip_netif.input(p, &lwip_netif);
		if (err != ERR_OK) {
			printf("err: %x\n");
			LWIP_DEBUGF(NETIF_DEBUG, ("btstack_network_process_packet: IP input error\n"));
				pbuf_free(p);
			p = NULL;
		}
	}
}

/** 
 * @brief Notify network interface that packet from send_packet_callback was sent and the next packet can be delivered.
 */
void btstack_network_packet_sent(void) {
	printf("btstack_network_packet_sent\n");
}

/**
 * @brief Get network name after network was activated
 * @note e.g. tapX on Linux, might not be useful on all platforms
 * @returns network name
 */
const char * btstack_network_get_name(void) {
	return "bt0";
}