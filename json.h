// {{{ header

#ifndef ___DHCPDUMP_JSON_H___
#define ___DHCPDUMP_JSON_H___

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

// }}}

// Minimal streaming JSON writer for the -j output. Values are written as
// they come, separators and nesting are tracked here. Strings escape every
// byte outside printable ASCII, so the output is plain ASCII and valid JSON
// whatever bytes it is given. A key is passed for members of an object and
// NULL for array elements (and for the outermost value).

#define JW_MAXDEPTH 10 // deepest nesting the -j schema uses is 8 (lists inside option 162 service parameters)

struct jw {
	FILE *f;
	int depth; // open objects/arrays
	unsigned n[JW_MAXDEPTH]; // members written so far at each level
	char close[JW_MAXDEPTH]; // '}' or ']' for each open level
};

void jw_init(struct jw *w,FILE *f);
void jw_obj(struct jw *w,const char *key); // open an object
void jw_arr(struct jw *w,const char *key); // open an array
void jw_end(struct jw *w); // close the innermost object or array
void jw_str(struct jw *w,const char *key,const char *s);
void jw_strn(struct jw *w,const char *key,const uint8_t *s,size_t n);
void jw_hex(struct jw *w,const char *key,const uint8_t *s,size_t n); // lower case hex string
void jw_uint(struct jw *w,const char *key,unsigned long v);
void jw_int(struct jw *w,const char *key,long v);
void jw_ip(struct jw *w,const char *key,const uint8_t *p); // dotted quad from 4 bytes
void jw_null(struct jw *w,const char *key);
void jw_true(struct jw *w,const char *key);
void jw_num(struct jw *w,const char *key,long long ip,unsigned long frac,int fdigits); // ip.frac, frac zero padded to fdigits

#endif
