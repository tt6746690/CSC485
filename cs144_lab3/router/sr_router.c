/**
 * Name: Peiqi Wang 
 * Userid: 1001132561
 * Description: 
 *      contains function to operate on routing table
 */
/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */


void set_eth(uint8_t *ethpkt, 
        uint8_t  *dhost,  /* NBO */
        uint8_t  *shost,  /* NBO */
        uint16_t  etype)  /* HBO */
{
    uint8_t dhost_tmp[ETHER_ADDR_LEN];
    uint8_t shost_tmp[ETHER_ADDR_LEN];
    SET_MAC(dhost_tmp, dhost);
    SET_MAC(shost_tmp, shost);

    sr_ethernet_hdr_t *ethhdr = (sr_ethernet_hdr_t *)ethpkt;

    SET_MAC(ethhdr->ether_shost, shost_tmp);
    SET_MAC(ethhdr->ether_dhost, dhost_tmp);
    ethhdr->ether_type = htons(etype);
}




void set_arppkt(
        uint8_t *arppkt, 
        uint16_t  op,   /* HBO */
        uint8_t  *sha,  /* NBO */
        uint32_t  sip,  /* NBO */
        uint8_t  *tha,  /* NBO */
        uint32_t  tip   /* NBO */
        ) {
    sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)arppkt;

    uint8_t sha_tmp[ETHER_ADDR_LEN];
    uint8_t tha_tmp[ETHER_ADDR_LEN];
    SET_MAC(sha_tmp, sha);
    SET_MAC(tha_tmp, tha);

    /* param independent fields */
    arphdr->ar_hrd = htons(arp_hrd_ethernet);
    arphdr->ar_pro = htons(ethertype_ip);
    arphdr->ar_hln = ETHER_ADDR_LEN;
    arphdr->ar_pln = 4;

    /* param dependent fields */
    arphdr->ar_op = htons(op);
    SET_MAC(arphdr->ar_sha, sha_tmp);
    arphdr->ar_sip = sip;
    SET_MAC(arphdr->ar_tha, tha_tmp);
    arphdr->ar_tip = tip;
}


/* recomputes checksum here */
void set_ippkt(
        uint8_t  *ippkt,
        int       ippkt_len,/* HBO, length op ip pkt starting at ip hdr */
        uint8_t   ip_p,   
        uint32_t  ip_src,   /* NBO */
        uint32_t  ip_dest   /* NBO */)
{
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)ippkt;

    iphdr->ip_v = 4;
    iphdr->ip_hl = 5;
    iphdr->ip_len = htons(ippkt_len);
    iphdr->ip_id = 0;                      /* may want to add one later */
    iphdr->ip_off = htons(IP_DF);          /* no fragmentation */
    iphdr->ip_ttl = 64;
    iphdr->ip_p = ip_p;
    iphdr->ip_src = ip_src;
    iphdr->ip_dst = ip_dest;
    ip_cksum(ippkt);
}


/* not setting data or calculating cksum here */
void set_icmppkt(
        uint8_t  *icmppkt,
        uint8_t   type,
        uint8_t   code)
{
    sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *)icmppkt;
    icmphdr->icmp_type = type;
    icmphdr->icmp_code = code;
}




void sr_send_arpquery(struct sr_instance *sr,
        uint32_t next_hop_ip)
{
    int len = ETH_HDR_SIZE + ARP_HDR_SIZE;
    uint8_t *packet = (uint8_t *)malloc(len);

    DECL_ETH(packet, len);
    DECL_ARP(packet, len);

    uint8_t arpquery_mac[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    /* outgoing interface ip and mac */
    sr_rt_t *rt_entry = sr_search_rt(sr, next_hop_ip);
    if(!rt_entry) { free(packet); return; }  /* not sending icmp error message when sending arp */
    sr_if_t *out_if = sr_get_interface(sr, rt_entry->interface);
    if(!out_if) { free(packet); return; }

    set_arppkt(arppkt, 
            arp_op_request, 
            out_if->addr, out_if->ip,      /* source, outgoing interface */
            arpquery_mac, next_hop_ip      /* target, to be filled by receiving client */
            );

    set_eth(ethpkt, 
            arpquery_mac,       /* dest: FF:FF:FF:FF:FF:FF */
            out_if->addr,       /* src:  outgoing interface's MAC */
            ethertype_arp);

    /* send out arp query */
    sr_send_packet(sr, packet, len, out_if->name);

    free(packet);
}



void sr_send_net_unreachable(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip) {
    FMT("sending ICMP Net Unreachable...\n");
    sr_send_icmp3(sr, packet, len, icmp_type_dst_unreachable, 0, next_hop_ip);
}

void sr_send_host_unreachable(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip) {
    FMT("sending ICMP Host Unreachable...\n");
    sr_send_icmp3(sr, packet, len, icmp_type_dst_unreachable, 1, next_hop_ip);
}

void sr_send_port_unreachable(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip) {
    FMT("sending ICMP Port Unreachable...\n");
    sr_send_icmp3(sr, packet, len, icmp_type_dst_unreachable, 3, next_hop_ip);
}

void sr_send_time_exceeded(struct sr_instance *sr, uint8_t *packet, int len, uint32_t next_hop_ip) {
    FMT("sending ICMP Time Exceeded...\n");
    sr_send_icmp3(sr, packet, len, icmp_type_time_exceeded, 0, next_hop_ip);
}

void sr_send_icmp3(struct sr_instance *sr, 
        uint8_t  *in_packet, 
        int       in_len, 
        uint8_t   type, 
        uint8_t   code,
        uint32_t  next_hop_ip)
{
    /* needs to free */
    int len = ETH_HDR_SIZE + IP_HDR_SIZE + ICMP3_HDR_SIZE;
    uint8_t *packet = (uint8_t *)calloc(len, 1);

    DECL_ETH(packet, len);
    DECL_IP(packet, len);
    DECL_ICMP3(packet, len);

    /* sets icmp3hdr */
    set_icmppkt(icmp3pkt, type, code);
    memcpy(icmp3hdr->data, in_packet+ETH_HDR_SIZE, ICMP_DATA_SIZE);
    icmp_t3_cksum(icmp3pkt, ICMP3_HDR_SIZE);

    /* sets iphdr */
    sr_rt_t *rt_entry = sr_search_rt(sr, next_hop_ip);
    if(!rt_entry) { free(packet); return; }  /* not sending icmp error message when sending icmp */
    sr_if_t *out_if = sr_get_interface(sr, rt_entry->interface);
    if(!out_if) { free(packet); return; }    /* ignore packets if router has inconsistent interface info */

    /* special case, for host unreachable, icmp's ip_src should be ip_dst of message causing the error */
    uint32_t sender_ip = out_if->ip;
    DECL_PKT_HDR(in_eth, in_packet, in_len, sr_ethernet_hdr_t);
    if(ETHTYPE_IS_IP(in_ethhdr)) {
        DECL_PKT_HDR(in_ip, in_packet + ETH_HDR_SIZE, in_len - ETH_HDR_SIZE, sr_ip_hdr_t);
        sr_if_t *TO_THIS_ROUTER = sr_get_interface_ip(sr, in_iphdr->ip_dst);
        if(TO_THIS_ROUTER && (IPP_IS_TCP(in_iphdr) || IPP_IS_UDP(in_iphdr))) {
            sender_ip = in_iphdr->ip_dst;
        }
    } 

    set_ippkt(ippkt, 
            len-ETH_HDR_SIZE, ip_protocol_icmp, 
            sender_ip, next_hop_ip);   /* switch src and dest ip */

    /* sets ethhdr and send out */
    sr_set_and_send_eth(
            sr, packet, len, 
            next_hop_ip, ethertype_ip);

    free(packet);
}



/* sets ethernet header with 
 *   find outgoing interface based on next_hop_ip 
 *      dest mac 
 *          query arpcache if cache hit, or 
 *          queue arpreq if cache miss
 *      src mac 
 *          iface's mac
 *      ether_type
 *          
 */
void sr_set_and_send_eth(struct sr_instance* sr, 
        uint8_t *packet, int len, 
        uint32_t next_hop_ip,   /* NBO */
        uint16_t etype          /* HBO */
        ) {
    DECL_ETH(packet, len);

    /* determine sender ip, for sending icmp error messages */
    uint32_t sendback_ip;
    if(ETHTYPE_IS_IP(ethhdr)) {
        DECL_IP(packet, len);
        sendback_ip = iphdr->ip_src;
    } else if(ETHTYPE_IS_ARP(ethhdr)) {
        DECL_ARP(packet, len);
        sendback_ip = arphdr->ar_sip;
    }

    /* ethertype */
    ethhdr->ether_type = htons(etype);

    /* src MAC */
    sr_rt_t *rt_entry = sr_search_rt(sr, next_hop_ip);
    if(!rt_entry) { 
        sr_send_net_unreachable(sr, packet, len, sendback_ip); return; }  
    sr_if_t *out_if = sr_get_interface(sr, rt_entry->interface);
    if(!out_if) { FMT("rtable interface not in sr->interface\n"); NO_REACH return; }

    SET_MAC(ethhdr->ether_shost, out_if->addr);

    /* look up arpcache for dst_ip -> dst_mac mapping
     *      If cache exists, fill in dest mac
     *      otherwise, queues arp request */
    struct sr_arpentry* ip_to_mac = 
        sr_arpcache_lookup(&sr->cache, next_hop_ip);
    if(ip_to_mac)
    {
        FMT("arp cache hit => sending/forwarding packet...");
        /* dest MAC */
        SET_MAC(ethhdr->ether_dhost, ip_to_mac->mac);
        sr_send_packet(sr, packet, len, out_if->name);
        free(ip_to_mac);
    } else {
        FMT("arp cache miss => push to arp queue...");
        struct sr_arpreq *req =
            sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, out_if->name);
        handle_arpreq(sr, req);
    }
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 * args:
 *  packet      byte array for the packet including ethernet header
 *  len         length of packet
 *  interface   the receiving interface
 *
 *  logics 
 *
 *  if ippkt
 *      If packet contains IP packet destined to router's interfaces
 *          if packet is ICMP (sr_p=1) echo request and checksum valid, send ICMP echo reply to sending host
 *          if packet contains TCP/UDP payload, send ICMP port number unreachable to sending host
 *          otherwise, ignore packet
 *      otherwise forward packet
 *  if arppkt
 *      ARP request to router's interface
 *          send ARP reply
 *      ARP reply to router's interface
 *          cache ARP reply
 *      ARP request not to router's interface
 *          flood to all outgoing interfaces (except incoming interface)
 *      ARP reply not to router's interface
 *          forward ARP to whichever ip it is destined to
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    fprintf(stderr, "****** -> Received packet of length %d \n",len);
    if((int)len < 0 || len > 1514) return;

    /* interface withwhich packet arrived at router */ 
    sr_if_t *in_if = sr_get_interface(sr, interface);

    DECL_ETH(packet, len);
    if(ETHTYPE_IS_IP(ethhdr)) {
        DECL_IP(packet, len);
        CHECK_CKSUM_IPPKT(ippkt);

        /* Check if packet destined for this router's interface */
        sr_if_t *TO_THIS_ROUTER = sr_get_interface_ip(sr, iphdr->ip_dst);
        if(TO_THIS_ROUTER) {
            if(IPP_IS_ICMP(iphdr)) {
                DECL_ICMP(packet, len);
                CHECK_CKSUM(icmppkt, len-(icmppkt-packet));
                if(!ICMP_IS_ECHO_REQUEST(icmphdr)) 
                    return;

                FMT("ICMP echo request => reply...\n");
                set_icmppkt(icmppkt, 
                        icmp_type_echo_reply, 0);
                icmp_cksum(icmppkt, len - (icmppkt - packet));

                set_ippkt(ippkt, 
                        len-ETH_HDR_SIZE, ip_protocol_icmp, 
                        iphdr->ip_dst, iphdr->ip_src);   /* switch src and dest ip */

                sr_set_and_send_eth(sr, 
                        packet, len, 
                        iphdr->ip_dst, ethertype_ip);

            } else if(IPP_IS_TCP(iphdr) || IPP_IS_UDP(iphdr)) {
                FMT("TCP UDP => port unreachable...\n");
                sr_send_port_unreachable(sr, packet, len, iphdr->ip_src);
            }
        } else {
            FMT("IP => forward ...\n");

            /* handle ttl over */
            if(IPTTL_OVER) {
                sr_send_time_exceeded(sr, packet, len, iphdr->ip_src);
                return;
            }
            iphdr->ip_ttl -= 1;
            ip_cksum(ippkt);

            sr_set_and_send_eth(sr, 
                    packet, len, 
                    iphdr->ip_dst, ethertype_ip);
        }
        return;
    } else if(ETHTYPE_IS_ARP(ethhdr)){
        DECL_ARP(packet, len);
        sr_if_t *iface = sr_get_interface_ip(sr, arphdr->ar_tip);

        if(iface && ARP_IS_REQ) 
        {
            FMT("arp req to router => reply...\n");

            set_arppkt(arppkt, 
                    arp_op_reply,
                    iface->addr, iface->ip,             /* source */
                    arphdr->ar_sha, arphdr->ar_sip);    /* target */

            set_eth(ethpkt, 
                    arphdr->ar_tha, in_if->addr, ethertype_arp);

            sr_send_packet(sr, packet, len, interface);
        } else if(iface && ARP_IS_REP) 
        {
            FMT("arp reply to router => cache...\n");
            handle_arpreply(sr, 
                    arphdr->ar_sha,     /* caching mac */
                    arphdr->ar_sip);    /* caching ip  */

        } else if(!iface && ARP_IS_REQ) {
            FMT("arp request (!this router) => forward\n");
            sr_set_and_send_eth(sr, 
                    packet, len, 
                    arphdr->ar_tip, ethertype_arp);
        } else if(!iface && ARP_IS_REP) {
            FMT("arp reply (!this router) => forward\n");
            sr_set_and_send_eth(sr, 
                    packet, len, 
                    arphdr->ar_tip, ethertype_arp);
        } else { NO_REACH }
        return;
    }

    FMT("...Ignoring this packets...\n");

}/* end sr_ForwardPacket */


