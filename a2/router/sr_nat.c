
#include <arpa/inet.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sr_nat.h"


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

    assert(nat);

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

    /* Initialize timeout thread */

    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

    /* Initialize any variables here */
    nat->mappings = NULL;
    nat->aux      = 1024;   /* avoids well-known ports 0~1023 */

    return success;
}


void sr_nat_conn_destroy(sr_nat_mapping_t* mapping) 
{
    
    if (mapping->type == nat_mapping_icmp) {
        assert(!mapping->conns);
        return;
    }

    sr_nat_connection_t* cur = NULL;
    sr_nat_connection_t* nxt = NULL;

    for (cur = mapping->conns; cur != NULL; cur = nxt) {
        nxt = cur->next;
        free(cur);
    }
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

    pthread_mutex_lock(&(nat->lock));

    /* free nat memory here */
    sr_nat_mapping_t* cur = NULL;
    sr_nat_mapping_t* nxt = NULL;

    for (cur = nat->mappings; cur != NULL; cur = nxt) {
        nxt = cur->next; 
        sr_nat_conn_destroy(cur);
        free(cur);
    }

    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
        pthread_mutexattr_destroy(&(nat->attr));
}



void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
    struct sr_nat *nat = (struct sr_nat *)nat_ptr;
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        /* fprintf(stderr, "NAT periodic timeout handling\n"); */

        /* handle periodic tasks here */
        time_t curtime = time(NULL);
        sr_nat_mapping_t* prev = NULL;
        sr_nat_mapping_t* map = NULL;
        sr_nat_mapping_t* next = NULL;

        for(map = nat->mappings; map != NULL; map = next) 
        {
            next = map->next;
            /* TODO: add tcp established and transitory condition */
            int cond = (map->type == nat_mapping_icmp && (curtime-map->last_updated) > nat->timeout_icmp);

            if (cond) {
                if (!prev) nat->mappings = next;
                else       prev->next = next;

                sr_nat_conn_destroy(map);
                free(map);
                continue;
            }
            prev = map; /* update only if not removing current map */
        }

        /* sr_nat_print(nat); */

        pthread_mutex_unlock(&(nat->lock));
    }
    return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL.
   For incoming packets from outside NAT */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    sr_nat_mapping_t* copy = NULL;
    sr_nat_mapping_t* entry = nat->mappings;

    while (entry) {
        if (entry->aux_ext == aux_ext && entry->type == type) {
            copy = (sr_nat_mapping_t*)malloc(sizeof(sr_nat_mapping_t));
            memcpy(copy, entry, sizeof(sr_nat_mapping_t));
            break;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. 
   For outgoing packets from behind NAT */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
    uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    sr_nat_mapping_t* copy = NULL;
    sr_nat_mapping_t* entry = nat->mappings;

    while (entry) {
        if (entry->ip_int == ip_int && entry->aux_int == aux_int && entry->type == type) {
            copy = (sr_nat_mapping_t*)malloc(sizeof(sr_nat_mapping_t));
            memcpy(copy, entry, sizeof(sr_nat_mapping_t));
            break;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
   For outgoing packets from behind the NAT
   Note inserting an entry already exists in mappings is equivalent to calling sr_nat_lookup_internal()
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
    uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a mapping, and then return a copy of it */
    sr_nat_mapping_t* mapping = NULL;

    /* check if already exists, if so just return that */
    mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
    if (mapping) 
        return mapping;

    /* Otherwise insert, TODO: populate _ext fields */
    mapping = (sr_nat_mapping_t *)calloc(1, sizeof(sr_nat_mapping_t));
    mapping->type           = type;
    mapping->ip_int         = ip_int;       /* internal client */
    mapping->aux_int        = aux_int;
    mapping->ip_ext         = nat->ip_ext;  /* external server */
    mapping->aux_ext        = htons(nat->aux++);    
    mapping->last_updated   = time(NULL);

    /* linking */
    mapping->next           = nat->mappings;
    nat->mappings           = mapping;

    /* consider cases where nat->aux wraps around */
    if (nat->aux == 0) nat->aux = 1024;

    /* Returns a new copy, needs to be freed */
    mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
    assert(mapping);

    pthread_mutex_unlock(&(nat->lock));
    return mapping;
}

void print_ip_addr(uint32_t ip) {
    uint32_t curOctet = ip >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 8) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 16) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 24) >> 24;
    fprintf(stderr, "%d", curOctet);
}

void sr_nat_print_mapping(sr_nat_mapping_t* mapping) {
    fprintf(stderr, "internal: (");
    print_ip_addr(ntohl(mapping->ip_int));
    fprintf(stderr, ", %d)", ntohs(mapping->aux_int));

    fprintf(stderr, " external: (");
    print_ip_addr(ntohl(mapping->ip_ext));
    fprintf(stderr, ", %d)", ntohs(mapping->aux_ext));

    fprintf(stderr, " time=%ld\n", mapping->last_updated);
}


void sr_nat_print(struct sr_nat* nat) {

    sr_nat_mapping_t *mapping = NULL;
    if(nat->mappings == NULL) {
        fprintf(stderr, "NAT mappings empty\n");
        return;
    }

    fprintf(stderr, "NAT mappings: \n");
    for(mapping = nat->mappings; mapping != NULL; mapping = mapping->next) {
        fprintf(stderr, "\t");
        sr_nat_print_mapping(mapping);
    }

}







