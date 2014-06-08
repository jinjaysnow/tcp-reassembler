#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "hashtbl.h"


static char *mystrdup(const char *s)
{
    char *b;
    if (!(b = malloc(strlen(s) + 1))) return NULL;
    strcpy(b, s);
    return b;
}

static hash_size def_hashfunc(const char *key)
{
    unsigned long hash = 5381;
    int c;

    while (0 != (c = *key++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

HASHTBL *hashtbl_create(hash_size size, hash_size (*hashfunc)(const char *))
{
    HASHTBL *hashtbl;

    assert(hashtbl = malloc(sizeof(HASHTBL)));
    assert(hashtbl->nodes = calloc(size, sizeof(struct hashnode_s *)));

    hashtbl->size = size;
    hashtbl->hashfunc = hashfunc ? hashfunc : def_hashfunc;

    return hashtbl;
}

size_t hashtbl_capacity(HASHTBL *hashtbl)
{
    size_t count = 0;
    for (int i = 0; i < hashtbl->size; i++)
    {
        if (hashtbl->nodes[i])
            count++;
    }
    return count;
}

size_t hashtbl_nodes_length(HASHNODE *node) {
    int count = 0;
    while (node) {
        count++;
        node = node->next;
    }
    return count;
}

void hashtbl_destroy(HASHTBL *hashtbl)
{
    hash_size n;
    struct hashnode_s *node, *oldnode;

    for (n = 0; n < hashtbl->size; ++n)
    {
        node = hashtbl->nodes[n];
        if (node)
            hashtbl_remove_n(node, -1, NULL);
    }
    free(hashtbl->nodes);
    free(hashtbl);
}

int hashtbl_index(HASHTBL *hashtbl, const char *key)
{
    hash_size hash = hashtbl->hashfunc(key) % hashtbl->size;
    HASHNODE *node = hashtbl->nodes[hash];

    if (node && !strcmp(node->key, key))
        return hash;
    return -1;
}

HASHNODE *hashtbl_get(HASHTBL *hashtbl, const char *key)
{
    hash_size hash = hashtbl_index(hashtbl, key);
    if (hash == -1)
        return NULL;
    return hashtbl->nodes[hash];
}

void hashtbl_rehash(HASHTBL *hashtbl)
{
    HASHNODE **oldnodes = hashtbl->nodes;
    HASHNODE **newnodes;
    hash_size newsize = 2 * hashtbl->size;
    assert(newnodes = calloc(newsize, sizeof(HASHNODE *)));

    for (int i = 0; i < hashtbl->size; i++)
    {
        if (!oldnodes[i])
            continue;
        hash_size hash = hashtbl->hashfunc(oldnodes[i]->key) % newsize;
        if (newnodes[hash]) {
            i = -1;
            newsize *= 2;
            free(newnodes);
            assert(newnodes = calloc(newsize, sizeof(HASHNODE *)));
        } else {
            newnodes[hash] = oldnodes[i];
        }
    }
    hashtbl->nodes = newnodes;
    hashtbl->size = newsize;
    free(oldnodes);
}

int hashtbl_insert(HASHTBL *hashtbl, const char *key, void *data)
{
    hash_size hash = hashtbl->hashfunc(key) % hashtbl->size;
    struct hashnode_s *node = hashtbl->nodes[hash];

    while (node)
    {
        if (!strcmp(node->key, key))
            break;
        hashtbl_rehash(hashtbl);
        hash = hashtbl->hashfunc(key) % hashtbl->size;
        node = hashtbl->nodes[hash];
    }

    assert(node = malloc(sizeof(struct hashnode_s)));
    assert(node->key = mystrdup(key));

    node->data = data;
    node->next = hashtbl->nodes[hash];
    hashtbl->nodes[hash] = node;

    return hash;
}

void hashtbl_remove_n(HASHNODE *node, int count, void (*data_free_func)(void *))
{
    if (!data_free_func)
        data_free_func = free;
    while (node)
    {
        HASHNODE *next = node->next;
        free(node->key);
        data_free_func(node->data);
        free(node);
        node = next;
        if (!(--count))
            break;
    }
}

void hashtbl_remove(HASHTBL *hashtbl, const char *key, void (*data_free_func)(void *))
{
    hash_size hash = hashtbl->hashfunc(key) % hashtbl->size;
    struct hashnode_s *node = hashtbl->nodes[hash];
    hashtbl_remove_n(node, -1, data_free_func);
    hashtbl->nodes[hash] = NULL;
}
