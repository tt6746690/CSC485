/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
    do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
            (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255


/* added macros */
#define MARK_USED(x) (x=x)
#define FMT(fmt, args...) \
    do { fprintf(stderr, fmt, ## args); } while(0)
#define NO_REACH FMT("should not reach here \n\t%s (%s, line %d)\n", __func__, __FILE__, __LINE__);

/* setting specific fields in hdr */
#define SET_MAC(dest, src) \
    do { \
        memcpy(dest, src, ETHER_ADDR_LEN); \
    } while(0)

#define SET_IP(dest, src) \
    do { \
        dst = htons(src); \
    } while(0)


/* struct size */
#define ETH_HDR_SIZE (sizeof(sr_ethernet_hdr_t))
#define IP_HDR_SIZE (sizeof(sr_ip_hdr_t))
#define ARP_HDR_SIZE (sizeof(sr_arp_hdr_t))
#define ICMP_HDR_SIZE (sizeof(sr_icmp_hdr_t))
#define ICMP3_HDR_SIZE (sizeof(sr_icmp_t3_hdr_t))
#define ETHIP_HDR_SIZE (ETH_HDR_SIZE+IP_HDR_SIZE)

/* BUF points to buffer where HDR_TYPE start, 
 * len is length of packet starting at BUF */
#define PKT_HDR_CAST(BUF, HDR_TYPE) ((HDR_TYPE *)(BUF))
#define DECL_PKT_HDR(NAME, BUF, LEN, HDR_TYPE) \
    uint8_t *NAME##pkt = (BUF); \
    if((LEN)<sizeof(HDR_TYPE)) { fprintf(stderr, "Incoming " #NAME "pkt too short\n"); } \
    HDR_TYPE *NAME##hdr= PKT_HDR_CAST(BUF, HDR_TYPE); \
    MARK_USED(NAME##pkt); \
    MARK_USED(NAME##hdr); \
    fprintf(stderr, "Declaring " #NAME " (%p, %lu) ...\n", &BUF, (unsigned long)(LEN)) \


/* consider packet starting at where hdr starts */
#define DECL_PKT_ETH(BUF, LEN)      DECL_PKT_HDR(eth,   BUF, LEN, sr_ethernet_hdr_t)
#define DECL_PKT_IP(BUF, LEN)       DECL_PKT_HDR(ip,    BUF, LEN, sr_ip_hdr_t)
#define DECL_PKT_ARP(BUF, LEN)      DECL_PKT_HDR(arp,   BUF, LEN, sr_arp_hdr_t)
#define DECL_PKT_ICMP(BUF, LEN)     DECL_PKT_HDR(icmp,  BUF, LEN, sr_icmp_hdr_t)
#define DECL_PKT_ICMP3(BUF, LEN)    DECL_PKT_HDR(icmp3, BUF, LEN, sr_icmp_t3_hdr_t)

/* consider packet starting from the very start */
#define DECL_ETH(BUF, LEN)      DECL_PKT_ETH(BUF, LEN)
#define DECL_IP(BUF, LEN)       DECL_PKT_IP(BUF+ETH_HDR_SIZE, LEN-ETH_HDR_SIZE)
#define DECL_ARP(BUF, LEN)      DECL_PKT_ARP(BUF+ETH_HDR_SIZE, LEN-ETH_HDR_SIZE)
#define DECL_ICMP(BUF, LEN)     DECL_PKT_ICMP(BUF+ETHIP_HDR_SIZE, LEN-ETHIP_HDR_SIZE)
#define DECL_ICMP3(BUF, LEN)    DECL_PKT_ICMP3(BUF+ETHIP_HDR_SIZE, LEN-ETHIP_HDR_SIZE)

/* ethernet */
#define ETHTYPE(hdr) (ntohs(hdr->ether_type))
/* requires _pkt declaration before hand */
#define ETHTYPE_IS_IP(ethhdr)  (ETHTYPE(ethhdr) == ethertype_ip)
#define ETHTYPE_IS_ARP(ethhdr) (ETHTYPE(ethhdr) == ethertype_arp)


/* checksum */
#define CHECK_CKSUM(BUF, LEN) \
    do { \
        if(cksum(BUF, LEN)) { fprintf(stderr, #BUF " packet (length %lu) has incorrect checksum %d\n", LEN, cksum(BUF, LEN)); } \
    } while(0)

#define CHECK_CKSUM_IPPKT(BUF) CHECK_CKSUM(BUF, IP_HDR_SIZE)
#define PACKET_DUMP_SIZE 1024

/* check ip's protocol type */
#define IPPROTO_IS_P(iphdr, protocol) (iphdr->ip_p == protocol)
/* requires _hdr declaration before hand */
#define IPP_IS_ICMP(iphdr) IPPROTO_IS_P(iphdr, ip_protocol_icmp)
#define IPP_IS_TCP(iphdr)  IPPROTO_IS_P(iphdr, ip_protocol_tcp)
#define IPP_IS_UDP(iphdr)  IPPROTO_IS_P(iphdr, ip_protocol_udp)
#define IPTTL_OVER ((iphdr->ip_ttl == 0) || (iphdr->ip_ttl == 1))

/* icmp */
#define CHECK_ICMP(icmphdr, type, code) (((icmphdr)->icmp_type == type) && ((icmphdr)->icmp_code == code))
/* assumes icmphdr declared before hand */
#define ICMP_IS_ECHO_REQUEST(icmphdr)        CHECK_ICMP(icmphdr, icmp_type_echo_request, 0)
#define ICMP_IS_ECHO_REPLY(icmphdr)          CHECK_ICMP(icmphdr, icmp_type_echo_reply, 0)
#define ICMP_IS_NET_UNREACHABLE(icmphdr)     CHECK_ICMP(icmphdr, icmp_type_dst_unreachable, 0)
#define ICMP_IS_HOST_UNREACHABLE(icmphdr)    CHECK_ICMP(icmphdr, icmp_type_dst_unreachable, 1)
#define ICMP_IS_PORT_UNREACHABLE(icmphdr)    CHECK_ICMP(icmphdr, icmp_type_dst_unreachable, 3)
#define ICMP_IS_TIME_EXCEEDED(icmphdr)       CHECK_ICMP(icmphdr, icmp_type_time_exceeded, 0)

/* arp */
/* assumes arphdr declared beforehand */
#define ARP_IS_REQ (ntohs(arphdr->ar_op)==(unsigned short)arp_op_request)
#define ARP_IS_REP (ntohs(arphdr->ar_op)==(unsigned short)arp_op_reply)


/* macro to facilitate return statement */
/* next_hop_ip --rt--> outgoing iface
 * If no IP found in rtable, send icmp Net unreachable */
#define OUTIF_FROM_NEXTHOPIP(ip) \
    sr_rt_t *rt_entry = sr_search_rt(sr, ip); \
    if(!rt_entry) {  \
        FMT("Next hop IP not found in rtable\n\t"); \
        print_addr_ip_int(ntohl(ip)); \
        sr_send_icmp_t3(sr, packet, iphdr->ip_src, icmp_type_dst_unreachable, 0); \
        return; \
    } \
    sr_if_t *out_if = sr_get_interface(sr, rt_entry->interface); \
    if(!out_if) { FMT("rtable interface not in sr->interface\n"); return; }

/* check for ttl = 0 or 1, send icmp time exceeded, 
 * otherwise decrement ttl and recompute cksum */
#define HANDLE_IPTTL \
        do { \
            if(IPTTL_OVER) { \
                FMT("ttl -> 0 => discarding packets\n"); \
                sr_send_time_exceeded(sr, packet, len, iphdr->ip_src); \
                return;  \
            } \
            iphdr->ip_ttl -= 1; \
            ip_cksum(ippkt); \
        } while(0); 


/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};



/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* setting packet headers */
void set_eth(uint8_t *ethpkt, 
        uint8_t  *dhost,  /* NBO */
        uint8_t  *shost,  /* NBO */
        uint16_t  etype   /* HBO */);

void set_arppkt(uint8_t *arppkt, 
        uint16_t  op,   /* HBO */
        uint8_t  *sha,  /* NBO */
        uint32_t  sip,  /* NBO */
        uint8_t  *tha,  /* NBO */
        uint32_t  tip   /* NBO */);

void set_ippkt(
        uint8_t  *ippkt,
        int       ippkt_len,/* HBO, length op ip pkt starting at ip hdr */
        uint8_t   ip_p,   
        uint32_t  ip_src,   /* NBO */
        uint32_t  ip_dest   /* NBO */);

void set_icmppkt(
        uint8_t  *icmppkt,
        uint8_t   type,
        uint8_t   code);

/* send arp query to next_hop_ip */
void sr_send_arpquery(struct sr_instance *sr,
                        uint32_t next_hop_ip);

/* forwarding pkts, change ethernet hdr only */
void sr_set_and_send_eth(struct sr_instance* sr, 
                        uint8_t *packet, int len, 
                        uint32_t next_hop_ip,   /* NBO */
                        uint16_t etype         /* HBO */
                        );

/* sending generated icmp message */
void sr_send_icmp3(struct sr_instance *sr, 
                        uint8_t  *in_packet, 
                        int       in_len, 
                        uint8_t   type, 
                        uint8_t   code,
                        uint32_t  next_hop_ip);

void sr_send_net_unreachable(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip);
void sr_send_host_unreachable(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip);
void sr_send_port_unreachable(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip);
void sr_send_time_exceeded(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip);


/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
