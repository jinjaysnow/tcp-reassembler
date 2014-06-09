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

#ifndef HASHTBL_H_INCLUDE_GUARD
#define HASHTBL_H_INCLUDE_GUARD

#include <stdlib.h>

typedef size_t hash_size;
typedef struct hashnode_s HASHNODE;

struct hashnode_s {
	char *key;
	void *data;
	HASHNODE *next;
};

typedef struct hashtbl {
	hash_size size;
	HASHNODE **nodes;
	hash_size (*hashfunc)(const char *);
} HASHTBL;


HASHTBL *hashtbl_create(hash_size size, hash_size (*hashfunc)(const char *));
void hashtbl_destroy(HASHTBL *hashtbl);
int hashtbl_index(HASHTBL *hashtbl, const char *key);
HASHNODE *hashtbl_get(HASHTBL *hashtbl, const char *key);
hash_size hashtbl_insert(HASHTBL *hashtbl, const char *key, void *data);
void hashtbl_remove_n(HASHNODE *node, int count, void (*data_free_func)(void *));
void hashtbl_remove(HASHTBL *hashtbl, const char *key, void (*data_free_func)(void *));

#endif
