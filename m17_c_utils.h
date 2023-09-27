#ifndef M17_C_UTILS_H
#define M17_C_UTILS_H

#include <string.h>

#include "m17_utils.h"
#include <QDebug>

/** character map for the C version */
const char * c_charMap = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/.";

/** encode an address (call sign) into base 40 */
static void m17_addr_cencode(char *addr_out, const char *addr_in, unsigned int in_len)
{
    long value = 0;
    long encoded = 0;
    if(in_len < 10) {
        if(0 == strcmp(addr_in, "ALL")) {
            encoded = 0xFFFFFFFFFFFF;
        }
        else {
            for (int i = (in_len - 1); i > -1; --i) {
                //qDebug()<<"Address[i]:"<<addr_in[i];
                value = strchr(c_charMap, addr_in[i]) - c_charMap;
                //qDebug()<<"Value index:"<<value<<c_charMap[value];
                if(value < 0) {
                    value = 0;
                }
                encoded = (encoded * 40) + value;
                //qDebug()<<"encoded["<<i<<"]:"<<encoded;
            }
        }
        //qDebug()<<"C Encoded Out:"<<encoded<<&encoded<<sizeof(encoded);
    }
    // now get the bytes from the long into the char *
    //memcpy(addr_out, &encoded, 8);
    for(int j=5; j > -1; --j) { // only the right-most 6 bytes matter
        // take the right most byte as a char into the output array
        memcpy(addr_out + j, &encoded, 1); // copy the least significant byte to the output array
        encoded >>= 8; // shift the bytes by 1 byte to set up the next one
        //qDebug()<<"encoded:"<<encoded;
    }
    return; // 6 bytes always
}

/** decode a base 40 address (call sign) into plain text */
static void m17_addr_cdecode(char *out, unsigned long encoded) {
    //"0000038fe411" = 59761681 = "AB4MW"
    if(encoded == 0xFFFFFFFFFFFF) {
        strncpy(out, "ALL", 3);
    }
    else if ((encoded == 0) || (encoded >= 0xEE6B28000000)){
        strncpy(out, "RESERVED", 8);
    }
    else {
        uint32_t idx = 0;
        while (encoded > 0) {
            //qDebug()<<"char:"<<c_charMap[encoded % 40];
            out[idx] = c_charMap[encoded % 40];
            encoded = encoded / 40;
            ++idx;
            //qDebug()<<"next enc:"<<encoded;
        }
        out[idx] = '\0';
    }
    //qDebug()<<"c decode out:"<<out;
}

// width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
// residue=0x0000 name="CRC-16/M17"
/** C version of building a CRC value based on CRC-16/M17 */
static unsigned short crc_ccitt_cbuild(unsigned char *data, unsigned long len) {

    unsigned long i, j, c, bit;
    unsigned long crc = crcinit;

    unsigned char * p = data;

    // fast bit by bit algorithm without augmented zero bytes.
    // does not use lookup table, suited for polynom orders between 1...32.

    for (i=0; i<len; i++) {

        c = (unsigned long)*p++;
        //if (refin) c = reflect(c, 8);

        for (j=0x80; j; j>>=1) {

            bit = crc & crchighbit;
            crc<<= 1;
            if (c & j) bit^= crchighbit;
            if (bit) crc^= polynom;
        }
    }

    //if (refout) crc=reflect(crc, order);
    crc^= crcxor;
    crc&= crcmask;

    return(crc);
}

// STILL NEED TO CREATE build LSF and build LICH functions here
/** build LSF from components */
static void build_c_LSF(char *lsf_out, char *dest, char *source, char *meta, \
                        bool isStream = true, int datatype = 1, int encryptionType = 0, \
                        int encryptionSubtype = 0, int can_type = 0, int reserved = 0)
{
    memcpy(&lsf_out[0], dest, 6);
    memcpy(&lsf_out[6], source, 6);
    unsigned short mask = 0; // mask takes in stream type, data type, enc type, enc subtype, can, and reserved bits
    if(isStream) {
        mask = 32768; // one in the left most bit 0x1000000000000000
    } // otherwise still 0 for false

    //qDebug()<<"Stream Mask:"<<mask;
    // data type 00 res, 01 data, 10 voice, 11 voice  + data
    switch(datatype) {
    case 0:break; // equiv to mask += 0;
    case 1: mask += DATATYPE; break;
    case 2: mask += VOICETYPE; break;
    case 3: mask += VOICEDATA; break;
    }
    memcpy(lsf_out + 13, (char *)&mask, 1);
    mask >>= 8;
    memcpy(lsf_out + 12, (char *)&mask, 1);

    memcpy(lsf_out + 14, meta, 14);

    // now add the CRC to the end
    uint16_t crc = crc_ccitt_cbuild((unsigned char*)lsf_out, 28);

    memcpy(lsf_out + 29, &crc, 1);
    crc >>=8;
    memcpy(lsf_out + 28, &crc, 1);

    return;
}

/*
Link Information Channel (LICH) The LICH allows for late listening and independent de-
coding to check destination address if the LSF for the current transmission was missed.
Each Stream Frame contains a 48-bit Link Information Channel (LICH). Each LICH within a
Stream Frame includes a 40-bit chunk of the 240-bit LSF frame that was used to establish the
stream. A 3-bit modulo 6 counter (LICH_CNT) is used to indicate which chunk of the LSF is
present in the current Stream Frame. LICH_CNT starts at 0, increments to 5, then wraps back
to 0.
Bits Content
0..39 40-bit chunk of full LSF Contents (Type 1 bits)
40..42 LICH_CNT
43..47 Reserved
Table 2.11: Link Information Channel Contents
Total: 48 bits
The 40-bit chunks start with the most significant byte of the LSF.
LICH_CNT LSF bits
0 239:200
1 199:160
2 159:120
3 119:80
4 79:40
5 39:0
Table 2.12: LICH_CNT and LSF bits
*/

static void build_c_LICH(char *lich_out, char * lsf, const int lich_cnt)
{
    //  const QByteArray LSF = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";
    //int32_t index = 0;
    unsigned char zero = 0, one = 32, two = 64, three = 96, four = 128, five = 160;
    int32_t idx = 0;
    switch(lich_cnt) {
    case 0:
        for(idx = 0; idx < 5 ; ++idx) {
            //qDebug()<<"out:"<<idx;
            lich_out[idx] = lsf[idx];
            //memcpy(lich_out + idx, lsf + idx, 1);
        }
        lich_out[5] = zero;
        break;
    case 1:
        for(idx = 5;idx < 10; ++idx) {
            lich_out[idx - 5] = lsf[idx];
        }
        lich_out[5] = one;
        break;
    case 2:
        for(idx = 10;idx < 15; ++idx) {
            lich_out[idx - 10] = lsf[idx];
        }
        lich_out[5] = two;
        break;
    case 3:
        for(idx = 15; idx < 20; ++idx) {
            lich_out[idx - 15] = lsf[idx];
        }
        lich_out[5] = three;
        break;
    case 4:
        for(idx = 20;idx < 25; ++idx) {
            lich_out[idx - 20] = lsf[idx];
        }
        lich_out[5] = four;
        break;
    case 5:
        for(idx = 25;idx < 30; ++idx) {
            lich_out[idx - 25] = lsf[idx];
        }
        lich_out[5] = five;
        break;
    }
    //qDebug()<<"LICH:"<<out;
    return;
}


/*
build_c_LSF(char *lsf_out, char *dest, char *source, char *meta, \
                        bool isStream = true, int datatype = 1, int encryptionType = 0, \
                        int encryptionSubtype = 0, int can_type = 0, int reserved = 0)
*/
static void build_c_streamFrame(char * frame_out, char * dest_address, char * source_address, char * meta_data, char * data_in, uint32_t data_size)
{
    const uint8_t ba_ZERO(0x00);
    // build LSF first using dest, source, and meta
    char dest[6];
    m17_addr_cencode(&dest[0], dest_address, strlen(dest_address));
    char source[6];
    m17_addr_cencode(&source[0], source_address, strlen(source_address));
    char lsfout[30];
    build_c_LSF(&lsfout[0], &dest[0], &source[0], meta_data); // 30 bytes


    //qDebug()<<"out=lsf:"<<out;

    // sever data into 16 byte chunks for frame building exercise below
    uint32_t chunkCount = data_size / 16;
    if((data_size % 16) > 0) ++chunkCount;
    uint32_t outsize = 30 + (chunkCount * 26);
    // Insert the LSF on the front
    unsigned char out[outsize];
    // add the LSF to the output buffer
    int32_t idx = 0; // start at the beginning! this is our pointer index
    for (idx = 0; idx < 30; ++idx) {
        out[idx] = (unsigned char)lsfout[idx];
    }

    //uint32_t lastChunkSize = data_size % 16;
    //qDebug()<<data.length()<<data.length()/16<<chunkCount<<dest<<source<<meta<<data;
    // for each chunk build the frame with LICH + Frame # w/EOS Flag, 16 bytes of data and 2 byte CRC
    for(int frnum = 0; frnum < chunkCount; ++frnum) { // "this"frnum" provides the frame ID
        // now build the lich based on frameNum % 6
        char lich[6];
        build_c_LICH(&lich[0], &lsfout[0], frnum % 6);
        // output the lich
        for(int j = 0; j < 6; ++j) {
            out[idx] = lich[j];
            ++idx;
        }

        // build the chunk from data_in
        uint8_t chunk[16] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; // each chunk must be 16 bytes or padded right with zeros
        for(int c = frnum * 16, x=0; x < 16; ++c, ++x) {
            chunk[x] = data_in[c];
        }

        // then create each data packet chunk and append them in order
        uint16_t framenum = (uint16_t)frnum; // for use in building output bytes later
        if(frnum == (chunkCount - 1)) { // last one so set EOS bit
            framenum += 32768u; // set left most bit to 1 add value to 0x1000000000000000
            //            qDebug()<<"FrameNum last:"<<((frameNum>>8) & 0xFF)<<((frameNum >>0) & 0xFF);
        }
        out[idx + 1] = (framenum & 0xFF);
        framenum >>= 8;
        out[idx] = (uint8_t)framenum;
        idx +=2;
        for(int m = 0; m < 16; ++m) {
            out[idx] = chunk[m];
            ++idx;
        }
        // add the CRC to the end two bytes
        qDebug()<<"idx:"<<idx<<"index of start of frame number before data chunk:"<<idx-18;
        uint16_t crc = crc_ccitt_cbuild(&out[idx - 18], 18); // start after LICH and get CRC on frame # and payload bytes (18)
        out[idx + 1] = (crc & 0xFF);
        crc >>= 8;
        out[idx] = (crc & 0xFF);
        memcpy(frame_out, out, outsize);
    }
    return;
}

#endif // M17_C_UTILS_H
