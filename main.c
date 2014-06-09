/*
 * This is a very troublesome homework...
 *
 * A pcap file structure for tcp transaction is something like this:
 *     [pcap_file_header]
 *     for each packet
 *         [pcap_packet]  this contains packet len info
 *         [ip_header]    usually of size 20 or more
 *         [tcp_header]   usually of size 20 or more
 *         [tcp_data]     len stored in ip header
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include "hashtbl.h"
#include "http_parser.h"
#include "main.h"

// my custom function
void error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    printf("\n");
    exit(EXIT_FAILURE);
}

char *mystrcat(int argc, const char *str1, ...) {
    va_list strs;
    va_start(strs, str1);
    char *ss = strdup(str1);
    unsigned int len = strlen(ss);

    for (int i = 0; i < argc - 1; i++) {
        const char *s = va_arg(strs, const char *);
        len += strlen(s);
        // 1 for '\0'
        if (!(ss = realloc(ss, len + 1)))
            error("alloc memory for `mystrcat` function failed");
        ss[len] = '\0';
        strcat(ss, s);
    }

    va_end(strs);
    return ss;
}

char *pathcat(char *dir, char *filename) {
    return mystrcat(3, dir, PATH_DELIMITER, filename);
}

size_t hexprint(void *ptr, size_t length) {
    size_t byte_counter = 0;
    char *byte_ptr = (char *)ptr;

    while (length--) {
        printf("%02X", *byte_ptr);
        byte_ptr++;

        if (++byte_counter) {
            if (byte_counter % 16 == 0) {
                printf("\n");
            } else if (byte_counter % 2 == 0) {
                printf(" ");
            }
        }
    }

    printf("\n");
    return byte_counter;
}

bool is_little_endian() {
   unsigned int i = 1;
   char *c = (char*)&i;
   return *c;
}

// judge function
bool is_pcap_file(const char *filename) {
    const char *sub = strrchr(filename, '.');
    if (sub == NULL)
        return FALSE;
    if (strcmp(sub, ".pcap"))
        return FALSE;
    return TRUE;
}

bool is_txt_file(const char *filename) {
    const char *sub = strrchr(filename, '.');
    if (sub == NULL)
        return FALSE;
    if (strcmp(sub, ".txt"))
        return FALSE;
    return TRUE;
}

bool is_ip4(int protocol) {
    return protocol == PROTOCOL_IP4;
}

bool is_ip6(int protocol) {
    return protocol == PROTOCOL_IP6;
}

bool is_ip(int protocol) {
    return is_ip4(protocol) || is_ip6(protocol);
}

bool is_tcp(void *ip_packet) {
    int protocol = get_ip_protocol(ip_packet);
    if (is_ip4(protocol))
        return _IP4(ip_packet)->ip_p == PROTOCOL_TCP;
    else if (is_ip6(protocol))
        return _IP6(ip_packet)->ip6_nxt == PROTOCOL_TCP;
    return FALSE;
}

bool is_udp(void *ip_packet) {
    int protocol = get_ip_protocol(ip_packet);
    if (is_ip4(protocol))
        return _IP4(ip_packet)->ip_p == PROTOCOL_UDP;
    else if (is_ip6(protocol))
        return _IP6(ip_packet)->ip6_nxt == PROTOCOL_UDP;
    return FALSE;
}

// packet infomation
int get_ether_type(byte *pcap_packet) {
    return ((int)(pcap_packet[12]) << 8) | (int)pcap_packet[13];
}
// IP
/*
 * @protocol: IPv4 or IPv6
 */
void *get_ip_header(byte *pcap_packet) {
    int offset;
    switch (get_ether_type(pcap_packet)) {
        case ETHER_TYPE_8021Q: offset = ETHER_OFFSET_8021Q;break;
        case ETHER_TYPE_IP4: offset = ETHER_OFFSET_IP4;break;
        case ETHER_TYPE_IP6: offset = ETHER_OFFSET_IP6;break;
        default: return NULL;
    }
    //skip past the Ethernet II header
    return (void *)(pcap_packet + offset);
}

void *get_ip_header_n(HASHNODE *node) {
    return get_ip_header(((pcap_item *)node->data)->packet);
}

int get_ip_protocol(void *ip_packet) {
    char version = *((char *)ip_packet);
    if (is_little_endian())
        version = (version & 0xF0) >> 4;
    else
        version &= 0x0F;

    return 4 == version ? PROTOCOL_IP4 : PROTOCOL_IP6;
}

// TCP
/*
 * @ip_packet: beginning memory address of IP packet, same with IP header
 */
tcp_hdr *get_tcp_header(void *ip_packet) {
    tcp_hdr *tcp_packet = NULL;
    int protocol = get_ip_protocol(ip_packet);
    if (is_ip4(protocol))
        tcp_packet = (tcp_hdr *)((char *)(ip_packet) + _IP4(ip_packet)->ip_hl * 4);
    else if (is_ip6(protocol))
        // 40 is IPv6 header length
        tcp_packet = (tcp_hdr *)((char *)(ip_packet) + 40);
    return tcp_packet;
}

tcp_hdr *get_tcp_header_p(byte *pcap_packet) {
    return get_tcp_header(get_ip_header(pcap_packet));
}

/*
 * return beginning memory address of tcp data
 */
byte *get_tcp_data(tcp_hdr *tcp_packet) {
    return (byte *)((char *)(tcp_packet) + tcp_packet->th_off * 4);
}

size_t get_tcp_data_length(void *ip_packet) {
    size_t ip_len = 0;
    size_t ip_header_len = 0;
    size_t tcp_header_len = 0;
    int protocol = get_ip_protocol(ip_packet);

    if (is_ip4(protocol)) {
        ip_header_len = _IP4(ip_packet)->ip_hl * 4;
        ip_len = ntohs(_IP4(ip_packet)->ip_len);
    } else {
        ip_len = ntohs(_IP6(ip_packet)->ip6_plen);
    }
    // `th_off` specifies the size of the TCP header in 32-bit words
    tcp_header_len = get_tcp_header(ip_packet)->th_off * 4;

    return ip_len - (ip_header_len + tcp_header_len);
}

size_t get_tcp_data_length_p(byte *pcap_packet) {
    return get_tcp_data_length(get_ip_header(pcap_packet));
}

size_t get_tcp_data_length_n(HASHNODE *node) {
    return get_tcp_data_length_p(((pcap_item *)node->data)->packet);
}

bool is_tcp_syn(tcp_hdr *tcp_packet) {
    return tcp_packet->th_flags & TH_SYN;
}

bool is_tcp_fin(tcp_hdr *tcp_packet) {
    return tcp_packet->th_flags & TH_FIN;
}

/*
 * return something like "192.168.137.1.80--192.168.137.233.8888"
 */
const char *get_ip_port_pair(void *ip_packet) {
    int addr_len;
    void *ip_src;
    void *ip_dst;
    int protocol = get_ip_protocol(ip_packet);

    if (is_ip4(protocol)) {
        addr_len = INET_ADDRSTRLEN;
        ip_src = &_IP4(ip_packet)->ip_src;
        ip_dst = &_IP4(ip_packet)->ip_dst;
    } else {
        addr_len = INET6_ADDRSTRLEN;
        ip_src = &_IP6(ip_packet)->ip6_src;
        ip_dst = &_IP6(ip_packet)->ip6_dst;
    }

    char buf_src[INET6_ADDRSTRLEN];
    char buf_dst[INET6_ADDRSTRLEN];
    inet_ntop(protocol, ip_src, buf_src, addr_len);
    inet_ntop(protocol, ip_dst, buf_dst, addr_len);

    tcp_hdr *tcp_packet = get_tcp_header(ip_packet);
    int port_src = ntohs(tcp_packet->th_sport);
    int port_dst = ntohs(tcp_packet->th_dport);

    // max port number in string takes 5 bytes
    char *str = malloc((addr_len + 5) * 2 + 5);
    sprintf(str, "%s.%d--%s.%d", buf_src, port_src, buf_dst, port_dst);

    return (const char *)str;
}

const char *reverse_ip_port_pair(const char *ip_port_pair) {
    char *pair2 = strstr(ip_port_pair, "--");
    char *pair1 = strndup(ip_port_pair, pair2 - ip_port_pair);
    // 2 is length of "--"
    return mystrcat(3, pair2 + 2, "--", pair1);
}

pcap_t *get_pcap_handle(char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (!(handle = pcap_open_offline(filename, errbuf)))
        error("Couldn't open pcap file %s: %s", filename, errbuf);
    return handle;
}

/*
 * a pcap item contains a pcap header and a pointer of beignning of packet
 */
pcap_item *create_pcap_item(const u_char *pcap_packet, struct pcap_pkthdr *pcap_header) {
    size_t pcap_len = pcap_header->caplen;
    u_char *tmp_packet = malloc(pcap_len);
    memcpy(tmp_packet, pcap_packet, pcap_len);

    pcap_item *pcap = malloc(sizeof(pcap_item));
    pcap->header = *pcap_header;
    pcap->packet = tmp_packet;

    return pcap;
}

// hash operation
/*
 * return a single instance of hash table
 */
static HASHTBL *_g_hashtbl = NULL;
HASHTBL *get_hash_table() {
    if(_g_hashtbl == NULL)
        assert(_g_hashtbl = hashtbl_create(HASH_SIZE, NULL));
    return _g_hashtbl;
}

/*
 * don't destory hash table until finished all your work!
 */
void destory_hash_table() {
    hashtbl_destroy(get_hash_table());
    _g_hashtbl = NULL;
}

void free_hash_node(void *ptr) {
    pcap_item *pcap = (pcap_item *)ptr;
    free((void *)pcap->packet);
    free((void *)pcap);
}

void remove_hash_nodes(const char *key) {
    hashtbl_remove(get_hash_table(), key, free_hash_node);
}

int get_hash_index(const char *key) {
    return hashtbl_index(get_hash_table(), key);
}

HASHNODE *get_hash_nodes(const char *key) {
    return hashtbl_get(get_hash_table(), key);
}

/*
 * use (source ip:port, destination ip:port) as key, hash pcap_item
 */
const char *insert_hash_node(byte *pcap_packet, struct pcap_pkthdr *pcap_header) {
    void *ip_packet = get_ip_header(pcap_packet);
    const char *key = get_ip_port_pair(ip_packet);
    pcap_item *pcap = create_pcap_item(pcap_packet, pcap_header);

    if (-1 == hashtbl_insert(get_hash_table(), key, (void *)pcap))
        error("ERROR: insert to hash table failed");
    return key;
}

int cmp_pcap_packet(pcap_item *p1, pcap_item *p2) {
    const u_char *packet1 = p1->packet;
    const u_char *packet2 = p2->packet;
    tcp_hdr *t1 = get_tcp_header_p(packet1);
    tcp_hdr *t2 = get_tcp_header_p(packet2);

    int diff_seq = ntohl(t1->th_seq) - ntohl(t2->th_seq);
    int diff_ack = ntohl(t1->th_ack) - ntohl(t2->th_ack);

    return diff_seq ? diff_seq : diff_ack;
}

/*
 * sort pcap packets storging in hash table
 */
HASHNODE *sort_pcap_packets(HASHNODE *list) {
    HASHNODE *p, *q, *e, *tail;
    int insize, nmerges, psize, qsize, i;

    if (!list)
        return NULL;

    insize = 1;
    while (1) {
        p = list;
        list = NULL;
        tail = NULL;
        /* count number of merges we do in this pass */
        nmerges = 0;

        while (p) {
            /* there exists a merge to be done */
            nmerges++;
            /* step `insize' places along from p */
            q = p;
            psize = 0;
            for (i = 0; i < insize; i++) {
                psize++;
                if (!(q = q->next))
                    break;
            }

            /* if q hasn't fallen off end, we have two lists to merge */
            qsize = insize;

            /* now we have two lists; merge them */
            while (psize > 0 || (qsize > 0 && q)) {
                /* decide whether next element of merge comes from p or q */
                if (psize == 0) {
                    /* p is empty; e must come from q. */
                    e = q; q = q->next; qsize--;
                } else if (qsize == 0 || !q) {
                    /* q is empty; e must come from p. */
                    e = p; p = p->next; psize--;
                } else if (cmp_pcap_packet((pcap_item *)p->data, (pcap_item *)q->data) <= 0) {
                    /* First element of p is lower (or same);
                     * e must come from p. */
                    e = p; p = p->next; psize--;
                } else {
                    /* First element of q is lower; e must come from q. */
                    e = q; q = q->next; qsize--;
                }

                /* add the next element to the merged list */
                if (tail)
                    tail->next = e;
                else
                    list = e;

                tail = e;
            }

            /* now p has stepped `insize' places along, and q has too */
            p = q;
        }

        tail->next = NULL;

        /* If we have done only one merge, we're finished. */
        if (nmerges <= 1)   /* allow for nmerges==0, the empty list case */
            return list;
        /* Otherwise repeat, merging lists twice the size */
        insize *= 2;
    }
}

tcp_hdr *get_tcp_header_n(HASHNODE *node) {
    return get_tcp_header_p(((pcap_item *)node->data)->packet);
}

HASHNODE *combine_hash_nodes(const char *key1, const char *key2) {
    HASHTBL *hashtbl = get_hash_table();
    hash_size hash1 = get_hash_index(key1);
    hash_size hash2 = get_hash_index(key2);
    HASHNODE *node1;
    HASHNODE *node2;

    // if one nodes is empty, then return another one
    if (hash1 == -1 || !(node1 = hashtbl->nodes[hash1]))
        return hashtbl->nodes[hash2];
    if (hash2 == -1 || !(node2 = hashtbl->nodes[hash2]))
        return hashtbl->nodes[hash1];

    // make sure of node1 being requester and node2 being responser
    unsigned char flags = get_tcp_header_n(node1)->th_flags;
    if ((flags & TH_SYN) && (flags & TH_ACK)) {
        hash_size tmp = hash1;
        hash1 = hash2;
        hash2 = hash1;
    }

    node2 = hashtbl->nodes[hash2];
    // exchange seq and ack, and append node2 to node1
    while (node2) {
        tcp_hdr *tcp_packet2 = get_tcp_header_n(node2);
        tcp_seq seq2 = tcp_packet2->th_seq;
        tcp_seq ack2 = tcp_packet2->th_ack;
        tcp_packet2->th_seq = ack2;
        tcp_packet2->th_ack = seq2;

        HASHNODE *next2 = node2->next;
        node2->next = hashtbl->nodes[hash1];
        hashtbl->nodes[hash1] = node2;
        node2 = next2;
    }
    hashtbl->nodes[hash2] = NULL;

    hashtbl->nodes[hash1] = node1 = sort_pcap_packets(hashtbl->nodes[hash1]);
    // recovery seq and ack in original node2
    while (node1) {
        void *ip_packet2 = get_ip_header_n(node1);
        const char *tmp = get_ip_port_pair(ip_packet2);
        if (!strcmp(key2, tmp)) {
            tcp_hdr *tcp_packet2 = get_tcp_header(ip_packet2);
            tcp_seq seq2 = tcp_packet2->th_seq;
            tcp_seq ack2 = tcp_packet2->th_ack;
            tcp_packet2->th_seq = ack2;
            tcp_packet2->th_ack = seq2;
        }
        node1 = node1->next;
        free((void *)tmp);
    }

    return hashtbl->nodes[hash1];
}

HASHNODE *combine_tcp_packet(hash_size index) {
    HASHTBL *hashtbl = get_hash_table();
    HASHNODE *node = hashtbl->nodes[index];
    HASHNODE *prev = node;
    HASHNODE *next;

    while (node) {
        next = node->next;
        // if no data, then skip it
        if (!get_tcp_data_length_n(node)) {
            if (hashtbl->nodes[index] == node)
                hashtbl->nodes[index] = next;
            else
                prev->next = next;
            free(node->key);
            free_hash_node(node->data);
            free(node);
        } else {
            prev = node;
        }
        node = next;
    }

    return hashtbl->nodes[index];
}
// file operation
/*
 * write pcap packet to pcap file
 */
void write_pcap_to_file(pcap_t *handle, HASHNODE *node) {
    const char *filename = pathcat(PCAP_DIR, mystrcat(2, node->key, ".pcap"));

    pcap_dumper_t *pd;
    if (!(pd = pcap_dump_open(handle, filename)))
        error("opening savefile '%s' failed for writing\n", filename);

    while (node) {
        pcap_item *pcap = (pcap_item *)node->data;
        struct pcap_pkthdr *pHeader = &pcap->header;
        const u_char *packet = pcap->packet;
        pcap_dump((u_char *)pd, pHeader, packet);
        node = node->next;
    }

    pcap_dump_close(pd);
    free((void *)filename);
}

void write_pcaps_to_files(pcap_t *handle) {
    HASHTBL *hashtbl = get_hash_table();

    for (int i = 0; i < hashtbl->size; i++) {
        if (!hashtbl->nodes[i])
            continue;
        hashtbl->nodes[i] = sort_pcap_packets(hashtbl->nodes[i]);
        write_pcap_to_file(handle, hashtbl->nodes[i]);
    }
    destory_hash_table();
}

/*
 * write tcp data (maybe contains HTTP request and response) to txt file
 */
size_t write_tcp_data_to_file(FILE *fp, byte *data_ptr, size_t data_len) {
    if (data_len && data_len != fwrite(data_ptr, 1, data_len, fp))
        error("write wrong size of tcp data to file\n");
    return data_len;
}

size_t write_tcp_data_to_file_n(FILE *fp, HASHNODE *node) {
    void *ip_packet = get_ip_header_n(node);
    tcp_hdr *tcp_packet = get_tcp_header(ip_packet);
    size_t data_len = get_tcp_data_length(ip_packet);
    byte *data_ptr = get_tcp_data(tcp_packet);
    return write_tcp_data_to_file(fp, data_ptr, data_len);
}

void write_http_data_to_files() {
    // read pcap files to memory
    DIR *dir;
    struct dirent *ent;
    if (!(dir = opendir(PCAP_DIR)))
        error("open directory '" PCAP_DIR "' failed\n");
    while ((ent = readdir(dir)) != NULL) {
        // deal with filename
        char *filename = ent->d_name;
        if (!is_pcap_file(filename))
            continue;
        char *pcap_filename = pathcat(PCAP_DIR, filename);

        const u_char *pcap_packet;
        struct pcap_pkthdr header;
        pcap_t *handle = get_pcap_handle(pcap_filename);
        while (NULL != (pcap_packet = pcap_next(handle, &header)))
            insert_hash_node(pcap_packet, &header);

        pcap_close(handle);
        free(pcap_filename);
    }
    closedir(dir);

    // write http requests and responses
    HASHTBL *hashtbl = get_hash_table();
    for (int i = 0; i < hashtbl->size; i++) {
        HASHNODE *node1 = hashtbl->nodes[i];
        if (!node1)
            continue;

        const char *key1 = node1->key;
        const char *key2 = reverse_ip_port_pair(key1);
        // combin two direction ip:port pair and write to file
        node1 = combine_hash_nodes(key1, key2);
        // delete all nodes having no data
        node1 = combine_tcp_packet(get_hash_index(node1->key));
        // skip empty file
        if (!node1)
            continue;
        char *filename = pathcat(REQS_DIR, mystrcat(2, node1->key, ".txt"));
        FILE *fp = fopen(filename, "wb");
        while (node1) {
            if (write_tcp_data_to_file_n(fp, node1) && node1->next)
                fwrite(REQUEST_GAP, 1, 4, fp);
            node1 = node1->next;
        }
        fclose(fp);
        free(filename);
        remove_hash_nodes(key1);
    }
}

// HTTP parse
int on_body(http_parser* _, const char* at, size_t length) {
  (void)_;
  printf("Body: %.*s\n", (int)length, at);
  return 0;
}

void http_file_parse(const char *filename) {
    // init http parser
    http_parser_settings settings;
    memset(&settings, 0, sizeof(settings));
    settings.on_body = on_body;
    http_parser parser;
    http_parser_init(&parser, HTTP_BOTH);
    // http_parser_init(&parser, HTTP_REQUEST);

    // read file into memory
    char* data;
    FILE *fp = fopen(filename, "rb");
    fseek(fp, 0, SEEK_END);
    long file_length = ftell(fp);
    if (file_length == -1)
        error("call ftell failed\n");
    data = malloc(file_length);
    fseek(fp, 0, SEEK_SET);
    if (fread(data, 1, file_length, fp) != (size_t)file_length) {
        free(data);
        error("couldn't read entire file\n");
    }
    fclose(fp);

    size_t nparsed = http_parser_execute(&parser, &settings, data, file_length);
    if (nparsed != (size_t)file_length) {
        free(data);
        error("%s: %s (%s)\n",
              filename,
              http_errno_description(HTTP_PARSER_ERRNO(&parser)),
              http_errno_name(HTTP_PARSER_ERRNO(&parser)));
    }
    free(data);
}

// END TODO
void parse_http_files() {
    DIR *dir;
    struct dirent *ent;
    if (!(dir = opendir(REQS_DIR)))
        error("open directory '" REQS_DIR "' failed\n");
    while ((ent = readdir(dir)) != NULL) {
        // deal with filename
        char *filename = ent->d_name;
        if (!is_txt_file(filename))
            continue;
        // filename = pathcat(REQS_DIR, filename);
        filename = "/Users/fz/Documents/codes/c/tcp-reassembler/requests/test.txt";
        http_file_parse(filename);
        // free(filename);
    }
    closedir(dir);
}

void init_environment(int argc, char **argv) {
    if (argc < 2)
        error("usage: %s [file]", argv[0]);
    mkdir(PCAP_DIR, 0754);
    mkdir(REQS_DIR, 0754);
    mkdir(HTTP_DIR, 0754);
}

#define DEBUG
int main(int argc, char **argv) {
    const u_char *pcap_packet;
    struct pcap_pkthdr header;
    pcap_t *handle;

#ifdef DEBUG
    argc = 2;
#endif
    init_environment(argc, argv);
#ifdef DEBUG
    handle = get_pcap_handle("/Users/fz/Documents/codes/c/tcp-reassembler/test.pcap");
#else
    handle = get_pcap_handle(argv[1]);
#endif

    while (NULL != (pcap_packet = pcap_next(handle, &header))) {
        void *ip_packet = get_ip_header(pcap_packet);
        // skip if neither IPv4 nor IPv6
        if (NULL == ip_packet)
            continue;
        if (is_tcp(ip_packet)) {
            insert_hash_node(pcap_packet, &header);
        } else if (is_udp(ip_packet)) {
            // TODO: deal with UDP
        }
    }

    write_pcaps_to_files(handle);
    write_http_data_to_files();
    destory_hash_table();

    parse_http_files();

    pcap_close(handle);
    return 0;
}
