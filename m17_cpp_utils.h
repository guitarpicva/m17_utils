#ifndef M17_CPP_UTILS_H
#define M17_CPP_UTILS_H

#include "m17_utils.h"

#include <stdlib.h>
#include <string>
#include <vector>

//#include <QDebug>
/** character map for the C++ stdlib version */
const std::string std_string_charMap = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/.";

/** stdlib : encode an address (call sign) in base 40 */
static std::vector<uint8_t> m17_addr_stdlib_encode(const std::string address) {
    long value = 0, encoded = 0;
    if(address.length() < 10) {
        if(address == "ALL") {
            encoded = 0xFFFFFFFFFFFF;
        }
        for (int i = (address.length() - 1); i > -1; --i) {
            value = std_string_charMap.find(address[i]);
            //qDebug()<<"String Value:"<<value<<address[i];
            if(value < 0) {
                value = 0;
            }
            encoded = (encoded * 40) + value;
            //qDebug()<<"Encoded:"<<encoded;
        }
        //qDebug()<<"Encoded:"<<encoded;
    }
    std::vector<uint8_t> v;
    v.reserve(6);
    // only the last 6 bytes of the long are important here
    for (size_t i = 2; i < sizeof(encoded); ++i) {
        v.insert(v.begin(), encoded & 0xFF);
        encoded >>= 8;
    }
    //qDebug()<<"V:"<<v<<v.size();
    //return encoded; // zero is an error
    return v;
}

/** decode a base 40 address (call sign) into plain text */
static std::string m17_addr_stdlib_decode(int64_t encoded) {
    //"0000038fe411"
    //qDebug()<<"decode:"<<encoded.toHex();
    std::string out = "";
    //ulong enc = std::stoul(encoded, 0, 16);
    //qDebug()<<"encoded:"<<encoded;//<<encoded.toHex().toLong(0, 16);
    if(encoded == -1) { //0xFFFFFFFFFFFFFFFF
        out = "ALL";
    }
    else if ((encoded == 0) || (encoded >= 0xEE6B28000000)) {
        out = "RESERVED";
    }
    else {
        while (encoded > 0) {
            //qDebug()<<"char:"<<charMap[enc % 40];
            out = out + std_string_charMap[encoded % 40];
            encoded = encoded / 40;
            //qDebug()<<"next enc:"<<enc;
        }
    }
    //qDebug()<<"stdlib out:"<<out.c_str();
    return out;
}

// width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
// residue=0x0000 name="CRC-16/M17"
/** C++ stdlib version of building a CRC value based on CRC-16/M17 */
static uint16_t crc_ccitt_cpp_build(std::vector<uint8_t> data) {

    /** CRC code adapted from http://www.zorc.breitbandkatze.de/crctester.c
 *  CRC tester v1.3 written on 4th of February 2003 by Sven Reifegerste (zorc/reflex)
 *  CRC configuration for M17:
 *  width=16 poly=0x5935 init=0xffff refin=false refout=false xorout=0x0000 check=0x772b
 *  residue=0x0000 name="CRC-16/M17"
*/
    const int32_t order = 16;
    const uint64_t polynom = 0x5935;
    const int32_t direct = 1;
    const uint64_t crcinit = 0xffff;
    const uint64_t crcxor = 0x0000;
    const int32_t refin = 0;
    const int32_t refout = 0;

    /** internal global CRC values: */
    // compute constant bit masks for whole CRC and CRC high bit
    uint64_t crcmask = ((((uint64_t)1<<(order-1))-1)<<1)|1;;
    uint64_t crchighbit = (uint64_t)1<<(order-1);
    uint64_t crcinit_direct = crcinit;

    uint64_t len = data.size();
    uint64_t i, j, c, bit;
    uint64_t crc = crcinit;
    uint8_t * p = (uint8_t*)data.data();
    // fast bit by bit algorithm without augmented zero bytes.
    // does not use lookup table, suited for polynom orders between 1...32.
    for (i=0; i<len; i++) {
        c = (uint64_t)*p++;
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

/** build LSF from components */
static std::vector<uint8_t> build_cpp_LSF(std::string dest, std::string source, std::string meta, \
                                          bool isStream = true, uint32_t datatype = 1, uint32_t encryptionType = 0, \
                                          uint32_t encryptionSubtype = 0, uint32_t can_type = 0, uint32_t reserved = 0)
{
    std::vector<uint8_t> out;
    std::vector<uint8_t> daddr = m17_addr_stdlib_encode(dest);
    std::vector<uint8_t> saddr = m17_addr_stdlib_encode(source);
    out.insert(out.begin(), daddr.begin(), daddr.end());
    out.insert(out.end(), saddr.begin(), saddr.end());

    uint16_t mask = 0; // mask takes in stream type, data type, enc type, enc subtype, can, and reserved bits
    if(isStream) {
        mask = 32768; // one in the left most bit 0x1000000000000000
    } // otherwise still 0 for false

    //qDebug()<<"Stream Mask:"<<mask;
    // data type 00 res, 01 data, 10 voice, 11 voice  + data
    const uint16_t DATATYPE = 8192U;
    const uint16_t VOICETYPE = 16384U;
    const uint16_t VOICEDATA = 24576U;
    switch(datatype) {
    case 0:break; // equiv to mask += 0;
    case 1: mask += DATATYPE; break;
    case 2: mask += VOICETYPE; break;
    case 3: mask += VOICEDATA; break;
    }

    out.push_back(mask & 0xFF);
    mask >>=8;
    out.insert(out.end() - 1, (mask & 0xFF));

    // add the meta data bytes
    out.insert(out.end(), meta.begin(), meta.end());

    // now add the CRC to the end
    uint16_t crc = crc_ccitt_cpp_build(out);
    out.push_back(crc & 0xFF);
    crc >>=8;
    out.insert(out.end() - 1, (crc& 0xFF));

    return out;
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
static std::vector<uint8_t> build_cpp_LICH(const std::vector<uint8_t> lsf, const int lich_cnt)
{
    //  const QByteArray LSF = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";
    //int32_t index = 0;
    uint8_t zero = 0, one = 32, two = 64, three = 96, four = 128, five = 160;
    std::vector<uint8_t> out;
    int32_t idx;
    switch(lich_cnt) {
    case 0:
        for(idx = 0; idx < 5 ; ++idx) {
            out.insert(out.end(), lsf.at(idx));
        }
        out.push_back(zero);
        break;
    case 1:
        for(idx = 5;idx < 10; ++idx) {
            out.insert(out.end(), lsf.at(idx));
        }
        out.push_back(one);
        break;
    case 2:
        for(idx = 10;idx < 15; ++idx) {
            out.insert(out.end(), lsf.at(idx));
        }
        out.push_back(two);
        break;
    case 3:
        for(idx = 15;idx < 20; ++idx) {
            out.insert(out.end(), lsf.at(idx));
        }
        out.push_back(three);
        break;
    case 4:
        for(idx = 20;idx < 25; ++idx) {
            out.insert(out.end(), lsf.at(idx));
        }
        out.push_back(four);
        break;
    case 5:
        for(idx = 25;idx < 30; ++idx) {
            out.insert(out.end(), lsf.at(idx));
        }
        out.push_back(five);
        break;
    }
    //qDebug()<<"LICH:"<<out;
    return out;
}

static std::vector<uint8_t> build_cpp_streamFrame(std::string dest_address,
                                                  std::string source_address,
                                                  std::string meta_data,
                                                  std::vector<uint8_t> data_in)
{
    std::vector<uint8_t> out;
    const uint8_t ba_ZERO(0x00);
    // build LSF first using dest, source, and meta
    const std::vector<uint8_t> lsf = build_cpp_LSF(dest_address, source_address, meta_data);
    // Insert the LSF on the front
    for(int i = 0; i < lsf.size(); ++i) {
        out.push_back(lsf.at(i));
    }
    //qDebug()<<"out=lsf:"<<out;
    // sever data into 16 byte chunks for frame building exercise below
    uint32_t chunkCount = data_in.size() / 16;
    if((data_in.size() % 16) > 0) ++chunkCount;
    uint32_t lastChunkSize = data_in.size() %16;
//    qDebug()<<data_in.size()<<data_in.size()/16<<chunkCount<<dest_address.c_str()<<source_address.c_str()<<meta_data.c_str()<<data_in;
    // for each chunk build the frame with LICH + Frame # w/EOS Flag, 16 bytes of data and 2 byte CRC
    for(uint32_t i = 0; i < chunkCount; ++i) {
        std::vector<uint8_t>::iterator first = (data_in.begin() + (i * 16));
        std::vector<uint8_t>::iterator last;
        if(i == chunkCount - 1) {
            last = (first + lastChunkSize);
        }
        else {
            last = (first + 16);
        }
        std::vector<uint8_t> chunk(first, last); // each chunk must be 16 bytes or padded right with zeros
        uint32_t max = 16 - chunk.size();
        // add zeros to explicitly extend the size of the QByteArray
        for(uint32_t j = 0; j < max; ++j) {
            // pad the last batch with zeros
            //qDebug()<<chunk.length()<<"pad end:";
            chunk.push_back(ba_ZERO);
        }
        //qDebug()<<"i:"<<i<<"chunk:"<<chunk<<chunk.size()<<last-first;
        uint16_t frameNum = (uint16_t)i; // for use in building output bytes later


        // now build the lich based on frameNum % 6
        std::vector<uint8_t> lich = build_cpp_LICH(lsf, i % 6);
        for(int k = 0; k < 6; ++k) {
            out.push_back(lich[k]);
        }
        // then create each data packet chunk and append them in order
        if(i == (chunkCount - 1)) { // last one so set EOS bit
            frameNum += 32768u; // set left most bit to 1 add value to 0x1000000000000000
//            qDebug()<<"FrameNum last:"<<((frameNum>>8) & 0xFF)<<((frameNum >>0) & 0xFF);
        }
//        else {
//            qDebug()<<"FrameNum first:"<<((frameNum>>8) & 0xFF)<<(frameNum & 0xFF);
//        }
        out.push_back((uint8_t)((frameNum >> 8) & 0xff));
        out.push_back((uint8_t)(frameNum & 0xff));

        for(int m = 0; m < 16; ++m) {
            out.push_back(chunk[m]);
        }
        std::vector<uint8_t> CRC(out.end() - 18, out.end());
        uint16_t crc = crc_ccitt_cpp_build(CRC);        
            out.push_back(crc & 0xFF);
            crc >>= 8;
            out.insert(out.end() - 1, (crc & 0xFF));
    }

    return out;
}
#endif // M17_CPP_UTILS_H
