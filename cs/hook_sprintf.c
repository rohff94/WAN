#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <dlfcn.h>

static int (*orig_sprintf)(const char *format, ...) = NULL;

int sprintf(const char *format, ...)
{
 if (orig_sprintf == NULL)
 {
  orig_sprintf = (int (*)(const char *format, ...))dlsym(RTLD_NEXT, "sprintf");
 }

 return orig_sprintf("within my own sprintf\n");
}
