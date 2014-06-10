/*
* @Author: fz
* @Date:   2014-06-09 19:17:17
* @Last Modified by:   fz
* @Last Modified time: 2014-06-10 14:44:05
*/

#include "util.h"

void *mymalloc(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr)
        error("alloc memory failed\n");
    return ptr;
}

void *mycalloc(size_t count, size_t size)
{
    void *ptr = calloc(count, size);
    if (!ptr)
        error("alloc memory failed\n");
    return ptr;
}

char *strnchr(const char *s, char ch, size_t n) {
    while (n--) {
        if (*s == ch)
            break;
        s++;
    }
    if (n == 0 && *s != ch)
        return NULL;
    return (char *)s;
}

void replacechr(char *str, char old, char new) {
    char *ptr;
    while (1) {
        ptr = strchr(str, old);
        if(ptr == NULL)
            break;
        str[(int)(ptr - str)]=new;
    }
}

char *mystrdup(const char *s)
{
    char *b;
    if (!(b = mymalloc(strlen(s) + 1))) return NULL;
    strcpy(b, s);
    return b;
}

void error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    printf("\n");
    exit(EXIT_FAILURE);
}

char *mystrcat(int argc, const char *str1, ...)
{
    va_list strs;
    va_start(strs, str1);
    char *ss = strdup(str1);
    unsigned long len = strlen(ss);

    for (int i = 0; i < argc - 1; i++)
    {
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

char *pathcat(const char *dir, const char *filename)
{
    return mystrcat(3, dir, PATH_DELIMITER, filename);
}

char *url2filename(const char *url) {
    size_t url_len = strlen(url);
    int offset = 0;
    const char *begin;;
    if (*url == '/') {
        if (url_len == 1)
            return strdup("index");
        offset = 1;
    }
    // end with '/' or can't find '/'
    const char *end = url + url_len - 1;
    if (*end == '/' || !(begin = strrchr(url, '/')))
        begin = url;


    if (*end != '/' && !(end = strchr(begin, '?')))
        end = url + url_len;

    return strndup(begin + offset, end - begin - offset);
}

size_t hexprint(void *ptr, size_t length)
{
    size_t byte_counter = 0;
    char *byte_ptr = (char *)ptr;

    while (length--)
    {
        printf("%02X", *byte_ptr);
        byte_ptr++;

        if (++byte_counter)
        {
            if (byte_counter % 16 == 0)
            {
                printf("\n");
            }
            else if (byte_counter % 2 == 0)
            {
                printf(" ");
            }
        }
    }

    printf("\n");
    return byte_counter;
}

bool is_little_endian()
{
    unsigned int i = 1;
    return *(char *)&i;
}

size_t getfilesize(FILE *fp) {
    fseek(fp, 0, SEEK_END);
    size_t data_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (data_len == -1) {
        fclose(fp);
        error("call ftell failed\n");
    }
    return data_len;
}
