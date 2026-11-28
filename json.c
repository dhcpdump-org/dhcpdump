// {{{ includes

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "json.h"

// }}}

static void jw_quote(FILE *f,const uint8_t *s,size_t n) { // {{{ a JSON string; anything outside printable ASCII is escaped, so packet data can never break out of it or reach a terminal raw
	size_t i;

	fputc('"',f);
	for (i=0;i<n;i++) {
		unsigned c=s[i];

		if (c=='"'||c=='\\') {
			fputc('\\',f);
			fputc((int)c,f);
		} else if (c<0x20||c>0x7e)
			fprintf(f,"\\u%04x",c);
		else
			fputc((int)c,f);
	}
	fputc('"',f);
} // }}}

static void jw_member(struct jw *w,const char *key) { // {{{ separator from the previous sibling, then the key when inside an object
	if (w->depth>0&&w->depth<=JW_MAXDEPTH&&w->n[w->depth-1]++) // past JW_MAXDEPTH there is no counter to keep; the writer never nests that deep
		fputc(',',w->f);
	if (key) {
		jw_quote(w->f,(const uint8_t *)key,strlen(key));
		fputc(':',w->f);
	}
} // }}}

static void jw_open(struct jw *w,const char *key,char open,char close) { // {{{
	jw_member(w,key);
	fputc(open,w->f);
	if (w->depth<JW_MAXDEPTH) {
		w->n[w->depth]=0;
		w->close[w->depth]=close;
	}
	w->depth++;
} // }}}

void jw_init(struct jw *w,FILE *f) { // {{{
	w->f=f;
	w->depth=0;
} // }}}

void jw_obj(struct jw *w,const char *key) { // {{{
	jw_open(w,key,'{','}');
} // }}}

void jw_arr(struct jw *w,const char *key) { // {{{
	jw_open(w,key,'[',']');
} // }}}

void jw_end(struct jw *w) { // {{{
	if (w->depth<=0)
		return;
	w->depth--;
	fputc(w->depth<JW_MAXDEPTH?w->close[w->depth]:'}',w->f);
} // }}}

void jw_str(struct jw *w,const char *key,const char *s) { // {{{
	jw_member(w,key);
	jw_quote(w->f,(const uint8_t *)s,strlen(s));
} // }}}

void jw_strn(struct jw *w,const char *key,const uint8_t *s,size_t n) { // {{{
	jw_member(w,key);
	jw_quote(w->f,s,n);
} // }}}

void jw_hex(struct jw *w,const char *key,const uint8_t *s,size_t n) { // {{{
	size_t i;

	jw_member(w,key);
	fputc('"',w->f);
	for (i=0;i<n;i++)
		fprintf(w->f,"%02x",s[i]);
	fputc('"',w->f);
} // }}}

void jw_uint(struct jw *w,const char *key,unsigned long v) { // {{{
	jw_member(w,key);
	fprintf(w->f,"%lu",v);
} // }}}

void jw_int(struct jw *w,const char *key,long v) { // {{{
	jw_member(w,key);
	fprintf(w->f,"%ld",v);
} // }}}

void jw_ip(struct jw *w,const char *key,const uint8_t *p) { // {{{
	jw_member(w,key);
	fprintf(w->f,"\"%u.%u.%u.%u\"",p[0],p[1],p[2],p[3]);
} // }}}

void jw_null(struct jw *w,const char *key) { // {{{
	jw_member(w,key);
	fputs("null",w->f);
} // }}}

void jw_true(struct jw *w,const char *key) { // {{{
	jw_member(w,key);
	fputs("true",w->f);
} // }}}

void jw_num(struct jw *w,const char *key,long long ip,unsigned long frac,int fdigits) { // {{{
	jw_member(w,key);
	fprintf(w->f,"%lld.%0*lu",ip,fdigits,frac);
} // }}}
