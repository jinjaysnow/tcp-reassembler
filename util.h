#ifndef _UTIL_H_INCLUDE_
#define _UTIL_H_INCLUDE_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#define PATH_DELIMITER "/"
#ifndef __FILE__
#define __FILE__ "main"
#endif /* __FILE__ */
#define TRUE 1
#define FALSE 0
#define CR 0x0D
#define LF 0x0A

typedef int bool;
typedef const unsigned char byte;

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

void *mymemmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
void *mymalloc(size_t size);
void *mycalloc(size_t count, size_t size);

char *strnchr(const char *s, char ch, size_t n);
void replacechr(char *str, char old, char new);
char *mystrdup(const char *s);
char *mystrcat(int argc, const char *str1, ...);
char *pathcat(const char *dir, const char *filename);
char *url2filename(const char *url);
size_t hexprint(void *ptr, size_t length);
size_t getfilesize(FILE *fp);

bool is_little_endian();

void error(const char *format, ...);


#endif /* _UTIL_H_INCLUDE_ */
