/* The authors of this work have released all rights to it and placed it
in the public domain under the Creative Commons CC0 1.0 waiver
(http://creativecommons.org/publicdomain/zero/1.0/).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Retrieved from: http://en.literateprograms.org/Hash_table_(C)?oldid=19620
*/
#include<string.h>
#include<stdio.h>
#include <stdint.h>
#include"hashtbl.h"

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

static char *mystrdup(const char *s)
{
	char *b;
	if(!(b=malloc(strlen(s)+1))) return NULL;
	strcpy(b, s);
	return b;
}

static hash_size def_hashfunc(const char * key) {
	// 42 is the answer of everything
	int len = 42;
	hash_size hash = len, tmp;
	int rem;

    if (len <= 0 || key == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    for (;len > 0; len--) {
        hash  += get16bits (key);
        tmp    = (get16bits (key+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        key  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (key);
                hash ^= hash << 16;
                hash ^= ((signed char)key[sizeof (uint16_t)]) << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (key);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += (signed char)*key;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

HASHTBL *hashtbl_create(hash_size size, hash_size (*hashfunc)(const char *))
{
	HASHTBL *hashtbl;

	if(!(hashtbl=malloc(sizeof(HASHTBL)))) return NULL;

	if(!(hashtbl->nodes=calloc(size, sizeof(struct hashnode_s*)))) {
		free(hashtbl);
		return NULL;
	}

	hashtbl->size=size;

	if(hashfunc) hashtbl->hashfunc=hashfunc;
	else hashtbl->hashfunc=def_hashfunc;

	return hashtbl;
}

void hashtbl_destroy(HASHTBL *hashtbl)
{
	hash_size n;
	struct hashnode_s *node, *oldnode;

	for(n=0; n<hashtbl->size; ++n) {
		node=hashtbl->nodes[n];
		while(node) {
			free(node->key);
			oldnode=node;
			node=node->next;
			free(oldnode);
		}
	}
	free(hashtbl->nodes);
	free(hashtbl);
}

int hashtbl_insert(HASHTBL *hashtbl, const char *key, void *data)
{
	hash_size hash = hashtbl->hashfunc(key) % hashtbl->size;
	hash_size rehash = hash;
	struct hashnode_s *node = hashtbl->nodes[hash];

/*	fprintf(stderr, "hashtbl_insert() key=%s, hash=%d, data=%s\n", key, hash, (char*)data);*/

	while(node) {
		if(!strcmp(node->key, key)) {
			node = node->next;
			continue;
		}

		rehash = (rehash + 1) % hashtbl->size;
		if (rehash == hash)
			return -1;
		node = hashtbl->nodes[rehash];
	}

	if(!(node = malloc(sizeof(struct hashnode_s))))
		return -1;
	if(!(node->key = mystrdup(key))) {
		free(node);
		return -1;
	}
	node->data = data;
	node->next = hashtbl->nodes[hash];
	hashtbl->nodes[hash] = node;

	return 0;
}

int hashtbl_remove(HASHTBL *hashtbl, const char *key, void (*data_free_func)(void *))
{
	struct hashnode_s *node;
    struct hashnode_s *next;
    if (!data_free_func)
        data_free_func = free;
	hash_size hash = hashtbl->hashfunc(key) % hashtbl->size;

	node = hashtbl->nodes[hash];
	while(node) {
        next = node->next;
		free(node->key);
        data_free_func(node->data);
		free(node);
        node = next;
	}
    hashtbl->nodes[hash] = NULL;

	return 0;
}
