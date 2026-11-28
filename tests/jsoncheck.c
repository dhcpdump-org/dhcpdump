// Check -j output read from stdin: every line is one strict RFC 8259 JSON
// object, in printable ASCII, without duplicate keys in any object, with
// "schema":1 at the top level. Prints the reason and exits 1 on the first bad
// line.

// {{{ includes

#include <stdio.h>
#include <string.h>

// }}}

// {{{ definitions

#define MAXLINE (1<<20)
#define MAXDEPTH 32
#define MAXKEYS 64
#define MAXKEY 64

static const char *p; // parse position in the current line
static const char *err; // first error found, NULL while the line is fine
static int schema_ok; // the top level object has "schema":1

// }}}

static void fail(const char *why) { // {{{ remember the first error only
	if (!err)
		err=why;
} // }}}

static void ws(void) { // {{{
	while (*p==' '||*p=='\t'||*p=='\r'||*p=='\n')
		p++;
} // }}}

static int hexdigit(char c) { // {{{
	return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
} // }}}

static void string(char *key,size_t keysz) { // {{{ a string at p; its raw (still escaped) text goes to key when given
	size_t n=0;
	int i;

	p++; // the opening quote
	while (!err&&*p!='"') {
		if (*p==0) {
			fail("unterminated string");
			return;
		}
		if ((unsigned char)*p<0x20) {
			fail("control character in string");
			return;
		}
		if (*p=='\\') {
			if (key&&n+1<keysz)
				key[n++]=*p;
			p++;
			if (*p=='u') {
				for (i=1;i<=4;i++)
					if (!hexdigit(p[i])) {
						fail("bad \\u escape");
						return;
					}
			} else if (!strchr("\"\\/bfnrt",*p)||*p==0) {
				fail("bad escape");
				return;
			}
		}
		if (key&&n+1<keysz)
			key[n++]=*p;
		p++;
	}
	if (key)
		key[n]=0;
	p++; // the closing quote
} // }}}

static void number(void) { // {{{ -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
	if (*p=='-')
		p++;
	if (*p=='0')
		p++;
	else if (*p>='1'&&*p<='9')
		while (*p>='0'&&*p<='9')
			p++;
	else {
		fail("bad number");
		return;
	}
	if (*p=='.') {
		p++;
		if (!(*p>='0'&&*p<='9')) {
			fail("bad fraction");
			return;
		}
		while (*p>='0'&&*p<='9')
			p++;
	}
	if (*p=='e'||*p=='E') {
		p++;
		if (*p=='+'||*p=='-')
			p++;
		if (!(*p>='0'&&*p<='9')) {
			fail("bad exponent");
			return;
		}
		while (*p>='0'&&*p<='9')
			p++;
	}
} // }}}

static void literal(const char *word) { // {{{
	size_t n=strlen(word);

	if (strncmp(p,word,n))
		fail("bad literal");
	else
		p+=n;
} // }}}

static void value(int depth);

static void object(int depth) { // {{{ an object at p; keys must be unique
	char keys[MAXKEYS][MAXKEY];
	const char *v;
	int nkeys=0,i;

	p++;
	ws();
	if (*p=='}') {
		p++;
		return;
	}
	while (!err) {
		if (*p!='"') {
			fail("expected a key");
			return;
		}
		if (nkeys==MAXKEYS) {
			fail("too many keys");
			return;
		}
		string(keys[nkeys],MAXKEY);
		if (err)
			return;
		for (i=0;i<nkeys;i++)
			if (!strcmp(keys[i],keys[nkeys])) {
				fail("duplicate key");
				return;
			}
		nkeys++;
		ws();
		if (*p!=':') {
			fail("expected a colon");
			return;
		}
		p++;
		ws();
		v=p;
		value(depth+1);
		if (depth==0&&!strcmp(keys[nkeys-1],"schema")&&p-v==1&&*v=='1')
			schema_ok=1;
		ws();
		if (*p=='}') {
			p++;
			return;
		}
		if (*p!=',') {
			fail("expected a comma or }");
			return;
		}
		p++;
		ws();
	}
} // }}}

static void array(int depth) { // {{{
	p++;
	ws();
	if (*p==']') {
		p++;
		return;
	}
	while (!err) {
		value(depth+1);
		ws();
		if (*p==']') {
			p++;
			return;
		}
		if (*p!=',') {
			fail("expected a comma or ]");
			return;
		}
		p++;
		ws();
	}
} // }}}

static void value(int depth) { // {{{
	if (depth>MAXDEPTH) {
		fail("nested too deep");
		return;
	}
	switch (*p) {
		case '{':
			object(depth);
			break;
		case '[':
			array(depth);
			break;
		case '"':
			string(NULL,0);
			break;
		case 't':
			literal("true");
			break;
		case 'f':
			literal("false");
			break;
		case 'n':
			literal("null");
			break;
		default:
			number();
			break;
	}
} // }}}

static char line[MAXLINE];

int main(void) { // {{{
	unsigned long n=0;
	size_t len,i;

	while (fgets(line,sizeof line,stdin)) {
		n++;
		len=strlen(line);
		err=NULL;
		schema_ok=0;
		if (len==0||line[len-1]!='\n')
			fail("line too long or no newline at the end");
		for (i=0;!err&&i+1<len;i++)
			if (line[i]<0x20||line[i]>0x7e)
				fail("not printable ASCII");
		p=line;
		if (!err&&*p!='{')
			fail("not an object");
		if (!err)
			value(0);
		if (!err&&*p!='\n')
			fail("data after the object");
		if (!err&&!schema_ok)
			fail("no \"schema\":1");
		if (err) {
			fprintf(stderr,"line %lu: %s\n",n,err);
			return 1;
		}
	}
	return 0;
} // }}}
