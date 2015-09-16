#ifndef EXPAT_CONFIG_H
#define EXPAT_CONFIG_H

/* 1234 = LIL_ENDIAN, 4321 = BIGENDIAN */
#define BYTEORDER 1234

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to specify how much context to retain around the current parse
   point. */
#define XML_CONTEXT_BYTES 1024

/* Define to make parameter entity parsing functionality available. */
//#define XML_DTD

/* Define to make XML Namespaces functionality available. */
//#define XML_NS

#endif  /* EXPAT_CONFIG_H */
