//#include <QCoreApplication>
#include "m17_qt_utils.h"
#include "m17_c_utils.h"
#include "m17_cpp_utils.h"
//#include <stdlib.h>
#include <QDebug>

int main(int argc, char *argv[])
{
    const QByteArray addr("AB4MW");
    QByteArray qaddrOut = m17_addr_qencode(addr);
    qDebug()<<"Encode AB4MW Qt:"<<qaddrOut;
    std::vector<uint8_t> cppaddrOut = m17_addr_stdlib_encode(addr.toStdString());
        qDebug()<<"Encode AB4MW stdlib:"<<cppaddrOut;
    char encodeout[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // encoded addresses are always 6 bytes
    m17_addr_cencode(encodeout, addr.toStdString().c_str(), addr.length());
    qDebug("Encode AB4MW c: %02x %02x %02x %02x %02x %02x", (unsigned char)encodeout[0], (unsigned char)encodeout[1], (unsigned char)encodeout[2], (unsigned char)encodeout[3], (unsigned char)encodeout[4], (unsigned char)encodeout[5]);

    char cdecoded[9]; // decoded addresses can be up to 9 bytes
    m17_addr_cdecode(cdecoded, 59761681u); //"AB4MW"
    qDebug("Decode AB4MW c: %s %02x %02x %02x %02x %02x %02x", &cdecoded[0], (unsigned char)cdecoded[0], (unsigned char)cdecoded[1], (unsigned char)cdecoded[2], (unsigned char)cdecoded[3], (unsigned char)cdecoded[4], (unsigned char)cdecoded[5]);
    qDebug()<<"Decode Qt EE:"<<m17_addr_qdecode(QByteArray::fromHex("EE6B28000000"));
    qDebug()<<"Decode Qt 0:"<<m17_addr_qdecode(QByteArray::fromHex("000000000000"));
    qDebug()<<"Decode Qt FF:"<<m17_addr_qdecode(QByteArray::fromHex("FFFFFFFFFFFF"));
    qDebug()<<"Decode Qt Encoded AB4MW:"<<m17_addr_qdecode(QByteArray::fromHex("0000038fe411"));
    qDebug()<<"Decode stdlib Encoded AB4MW (59761681):"<<m17_addr_stdlib_decode(59761681u).c_str();
    qDebug()<<"Decode stdlib Encoded EE:"<<m17_addr_stdlib_decode(262144000000000u).c_str();
    qDebug()<<"Decode stdlib Encoded 0 :"<<m17_addr_stdlib_decode(0).c_str();
    qDebug()<<"Decode stdlib Encoded FF:"<<m17_addr_stdlib_decode(0xffffffffffffffffu).c_str();

    qDebug()<<"qCRC for test frame (54412):"<<crc_ccitt_qbuild(QByteArray::fromHex("0000038fe411000003b5819fa0003132333435363738393031323334"));
    qDebug()<<"qCRC for 123456789:"<<crc_ccitt_qbuild(QString("123456789").toLatin1());
    qDebug()<<"qCRC for A:"<<crc_ccitt_qbuild(QString("A").toLatin1());
    qDebug()<<"qCRC for <empty>:"<<crc_ccitt_qbuild(QString("").toLatin1());

    qDebug()<<"cCRC for 123456789:"<<crc_ccitt_cbuild((unsigned char*)"123456789", 9);
    qDebug()<<"cCRC for A:"<<crc_ccitt_cbuild((unsigned char*)"A", 1);
    qDebug()<<"cCRC for <empty>:"<<crc_ccitt_cbuild((unsigned char*)"", 0);

    std::vector<uint8_t> in = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    uint16_t crcout = crc_ccitt_cpp_build(in);
    qDebug("cppCRC for 123456789: %04x %d", crcout, crcout);

    in.clear();
    in.push_back('A');
    crcout = crc_ccitt_cpp_build(in);
    qDebug("cppCRC for A: %04x %d", crcout, crcout);

    in.clear();
    crcout = crc_ccitt_cpp_build(in);
    qDebug("cppCRC for <empty>: %04x %d", crcout, crcout);
    qDebug()<<"--------------------------------------------------------------------------------------";

    const QByteArray LSF = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";

    QByteArray qLSF = build_qLSF(m17_addr_qencode("AB4MW"), m17_addr_qencode("G4KLX"), "12345678901234");
    qDebug()<<"LSF Qt test:"<<qLSF.toHex();

    char *dcall = "AB4MW", *scall = "G4KLX";
    char cmeta[14] = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4'};
    qDebug()<<"Dest length:"<<strlen(dcall);
    m17_addr_cencode(&encodeout[0], dcall, strlen(dcall)); // have to know the length of the call sign
    char destcall[6];
    memcpy(&destcall[0], &encodeout[0], 6);
    m17_addr_cencode(&encodeout[0], scall, strlen(scall)); // have to know the length of the call sign
    char sourcecall[6];
    char lsfOut[30];
    memcpy(&sourcecall[0], &encodeout[0], 6);
    build_c_LSF(&lsfOut[0], &destcall[0], &sourcecall[0], &cmeta[0]);
    qDebug("LSF C : %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ", (unsigned char)lsfOut[0], (unsigned char)lsfOut[1], (unsigned char)lsfOut[2], (unsigned char)lsfOut[3], (unsigned char)lsfOut[4], (unsigned char)lsfOut[5], (unsigned char)lsfOut[6], (unsigned char)lsfOut[7], (unsigned char)lsfOut[8], (unsigned char)lsfOut[9], (unsigned char)lsfOut[10], (unsigned char)lsfOut[11], (unsigned char)lsfOut[12], (unsigned char)lsfOut[13], (unsigned char)lsfOut[14]);
    qDebug("        %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",  (unsigned char)lsfOut[15], (unsigned char)lsfOut[16], (unsigned char)lsfOut[17], (unsigned char)lsfOut[18], (unsigned char)lsfOut[19], (unsigned char)lsfOut[20], (unsigned char)lsfOut[21], (unsigned char)lsfOut[22], (unsigned char)lsfOut[23], (unsigned char)lsfOut[24], (unsigned char)lsfOut[25], (unsigned char)lsfOut[26], (unsigned char)lsfOut[27], (unsigned char)lsfOut[28], (unsigned char)lsfOut[29]);

    std::vector<uint8_t> cppLSF;
    cppLSF = build_cpp_LSF(m17_addr_stdlib_encode("AB4MW"), m17_addr_stdlib_encode("G4KLX"), "12345678901234");
    qDebug()<<"LSF stdlib test:"<<cppLSF;

    qDebug()<<"qLICH for qLSF 0"<<build_qLICH(qLSF, 0).toHex();
    qDebug()<<"qLICH for qLSF 1"<<build_qLICH(qLSF, 1).toHex();
    qDebug()<<"qLICH for qLSF 2"<<build_qLICH(qLSF, 2).toHex();
    qDebug()<<"qLICH for qLSF 3"<<build_qLICH(qLSF, 3).toHex();
    qDebug()<<"qLICH for qLSF 4"<<build_qLICH(qLSF, 4).toHex();
    qDebug()<<"qLICH for qLSF 5"<<build_qLICH(qLSF, 5).toHex();

    qDebug()<<"cppLICH for cppLSF 0"<<build_cpp_LICH(cppLSF, 0);
    qDebug()<<"cppLICH for cppLSF 1"<<build_cpp_LICH(cppLSF, 1);
    qDebug()<<"cppLICH for cppLSF 2"<<build_cpp_LICH(cppLSF, 2);
    qDebug()<<"cppLICH for cppLSF 3"<<build_cpp_LICH(cppLSF, 3);
    qDebug()<<"cppLICH for cppLSF 4"<<build_cpp_LICH(cppLSF, 4);
    qDebug()<<"cppLICH for cppLSF 5"<<build_cpp_LICH(cppLSF, 5);

    char clichOut[6];
    //qDebug("%02x %02x %02x %02x %02x %02x", lsfOut[0], lsfOut[1], lsfOut[2], lsfOut[3], lsfOut[4], lsfOut[5]);
    build_c_LICH(&clichOut[0], &lsfOut[0], 0);
    qDebug("clichOut 0: %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 1);
    qDebug("clichOut 1: %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 2);
    qDebug("clichOut 2: %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 3);
    qDebug("clichOut 3: %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 4);
    qDebug("clichOut 4: %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 5);
    qDebug("clichOut 5: %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );

    qDebug()<<"build_qstreamFrame:"<<build_qstreamFrame("AB4MW", "G4KLX", "12345678901234", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456").toHex();
    std::vector<uint8_t> strframe = build_cpp_streamFrame("AB4MW", "G4KLX", "12345678901234", in);
    qDebug()<<"build_cpp_streamFrame:"<<strframe<<strframe.size();
    return 0;
}
