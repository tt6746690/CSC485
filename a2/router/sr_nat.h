
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
    nat_mapping_icmp,
    nat_mapping_tcp
    /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
    /* add TCP connection state data members here */

    struct sr_nat_connection *next;
};
typedef struct sr_nat_connection sr_nat_connection_t;

struct sr_nat_mapping {
    sr_nat_mapping_type type;
    uint32_t ip_int; /* internal ip addr */
    uint32_t ip_ext; /* external ip addr */
    uint16_t aux_int; /* internal port or icmp id */
    uint16_t aux_ext; /* external port or icmp id */
    time_t last_updated; /* use to timeout mappings */
    struct sr_nat_connection *conns; /* list of connections. null for ICMP */
    struct sr_nat_mapping *next;
};
typedef struct sr_nat_mapping sr_nat_mapping_t;

struct sr_nat {
    /* NAT table mappings */
    struct sr_nat_mapping *mappings;

    /* globally unique port or icmp id, set in sr_nat_init */ 
    uint32_t aux;           /* HBO */

    /* router's external interface, set in sr_handle_hwinfo */
    uint32_t ip_ext;        /* NBO */

    /* timeouts, set in main */
    int nat_on;
    int timeout_icmp;
    int timeout_tcp_established;
    int timeout_tcp_transitory;

    /* threading, set in sr_nat_init */
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
    pthread_attr_t thread_attr;
    pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Prints the list of mappings */
void sr_nat_print(struct sr_nat* nat);


#endif
