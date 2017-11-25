/*-----------------------------------------------------------------------------
 * file:  sr_rt.h 
 * date:  Mon Oct 07 03:53:53 PDT 2002  
 * Author: casado@stanford.edu
 *
 * Description:
 *
 * Methods and datastructures for handeling the routing table
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>

#include "sr_if.h"

/* ----------------------------------------------------------------------------
 * struct sr_rt
 *
 * Node in the routing table 
 * functions as a destIP -> router outgoing interface mapping
 * -------------------------------------------------------------------------- */

struct sr_rt
{
    struct in_addr dest;            /* 4 byte IP addr */
    struct in_addr gw;
    struct in_addr mask;
    char   interface[sr_IFACE_NAMELEN];
    struct sr_rt* next;
};
typedef struct sr_rt sr_rt_t;


/* search in routing table with matching dst_ip to ip provided 
 * returns a non-owning pointer to a node, (do not free), 0 if not found*/
sr_rt_t* sr_search_rt(struct sr_instance *sr, uint32_t ip);

int sr_load_rt(struct sr_instance*,const char*);
void sr_add_rt_entry(struct sr_instance*, struct in_addr,struct in_addr,
                  struct in_addr, char*);
void sr_print_routing_table(struct sr_instance* sr);
void sr_print_routing_entry(struct sr_rt* entry);


#endif  /* --  sr_RT_H -- */
