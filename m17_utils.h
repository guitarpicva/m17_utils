#ifndef M17_UTILS_H
#define M17_UTILS_H
/** CRC code adapted from http://www.zorc.breitbandkatze.de/crctester.c
 *  CRC tester v1.3 written on 4th of February 2003 by Sven Reifegerste (zorc/reflex)
 *  CRC configuration for M17:
 *  width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
 *  residue=0x0000 name="CRC-16/M17"
*/
const int order = 16;
const unsigned long polynom = 0x5935;
const int direct = 1;
const unsigned long crcinit = 0xffff;
const unsigned long crcxor = 0x0000;
const int refin = 0;
const int refout = 0;
const unsigned short DATATYPE = 8192U;
const unsigned short VOICETYPE = 16384U;
const unsigned short VOICEDATA = 24576U;

/** internal global CRC values: */
// compute constant bit masks for whole CRC and CRC high bit
unsigned long crcmask = ((((unsigned long)1<<(order-1))-1)<<1)|1;;
unsigned long crchighbit = (unsigned long)1<<(order-1);
unsigned long crcinit_direct = crcinit;
// END CRC Defaults
#endif // M17_UTILS_H
