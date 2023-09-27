//#include <QCoreApplication>
#include "m17_qt_utils.h"
#include "m17_c_utils.h"
#include "m17_cpp_utils.h"

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

    std::vector<uint8_t> in = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34};
    std::vector<uint8_t> indata = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34};
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

    char dcall[6] = {'A', 'B', '4', 'M', 'W', 0};
    char scall[6] = {'G', '4', 'K', 'L', 'X', 0};
    char cmeta[14] = {'1','2','3','4','5','6','7','8','9','0','1','2','3','4'};
    qDebug()<<"Dest length:"<<strlen(dcall);
    m17_addr_cencode(&encodeout[0], &dcall[0], strlen(dcall)); // have to know the length of the call sign
    char destcall[6];
    memcpy(&destcall[0], &encodeout[0], 6);
    m17_addr_cencode(&encodeout[0], &scall[0], strlen(scall)); // have to know the length of the call sign
    char sourcecall[6];
    char lsfOut[30];
    memcpy(&sourcecall[0], &encodeout[0], 6);
    build_c_LSF(&lsfOut[0], &destcall[0], &sourcecall[0], &cmeta[0]);
    qDebug("cLSF : %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ", (unsigned char)lsfOut[0], (unsigned char)lsfOut[1], (unsigned char)lsfOut[2], (unsigned char)lsfOut[3], (unsigned char)lsfOut[4], (unsigned char)lsfOut[5], (unsigned char)lsfOut[6], (unsigned char)lsfOut[7], (unsigned char)lsfOut[8], (unsigned char)lsfOut[9], (unsigned char)lsfOut[10], (unsigned char)lsfOut[11], (unsigned char)lsfOut[12], (unsigned char)lsfOut[13], (unsigned char)lsfOut[14]);
    qDebug("       %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",  (unsigned char)lsfOut[15], (unsigned char)lsfOut[16], (unsigned char)lsfOut[17], (unsigned char)lsfOut[18], (unsigned char)lsfOut[19], (unsigned char)lsfOut[20], (unsigned char)lsfOut[21], (unsigned char)lsfOut[22], (unsigned char)lsfOut[23], (unsigned char)lsfOut[24], (unsigned char)lsfOut[25], (unsigned char)lsfOut[26], (unsigned char)lsfOut[27], (unsigned char)lsfOut[28], (unsigned char)lsfOut[29]);

    std::vector<uint8_t> cppLSF;
    cppLSF = build_cpp_LSF(m17_addr_stdlib_encode("AB4MW"), m17_addr_stdlib_encode("G4KLX"), "12345678901234");
    qDebug()<<"LSF stdlib test:"<<cppLSF;

    qDebug()<<"qLICH for qLSF 0:   "<<build_qLICH(qLSF, 0).toHex(' ');
    qDebug()<<"qLICH for qLSF 1:   "<<build_qLICH(qLSF, 1).toHex(' ');
    qDebug()<<"qLICH for qLSF 2:   "<<build_qLICH(qLSF, 2).toHex(' ');
    qDebug()<<"qLICH for qLSF 3:   "<<build_qLICH(qLSF, 3).toHex(' ');
    qDebug()<<"qLICH for qLSF 4:   "<<build_qLICH(qLSF, 4).toHex(' ');
    qDebug()<<"qLICH for qLSF 5:   "<<build_qLICH(qLSF, 5).toHex(' ');

    std::vector<uint8_t> cpplich = build_cpp_LICH(cppLSF, 0);
    qDebug("cppLICH for cppLSF 0: %02x %02x %02x %02x %02x %02x", cpplich[0], cpplich[1], cpplich[2], cpplich[3], cpplich[4], cpplich[5]);
    cpplich = build_cpp_LICH(cppLSF, 1);
    qDebug("cppLICH for cppLSF 1: %02x %02x %02x %02x %02x %02x", cpplich[0], cpplich[1], cpplich[2], cpplich[3], cpplich[4], cpplich[5]);
    cpplich = build_cpp_LICH(cppLSF, 2);
    qDebug("cppLICH for cppLSF 2: %02x %02x %02x %02x %02x %02x", cpplich[0], cpplich[1], cpplich[2], cpplich[3], cpplich[4], cpplich[5]);
    cpplich = build_cpp_LICH(cppLSF, 3);
    qDebug("cppLICH for cppLSF 3: %02x %02x %02x %02x %02x %02x", cpplich[0], cpplich[1], cpplich[2], cpplich[3], cpplich[4], cpplich[5]);
    cpplich = build_cpp_LICH(cppLSF, 4);
    qDebug("cppLICH for cppLSF 4: %02x %02x %02x %02x %02x %02x", cpplich[0], cpplich[1], cpplich[2], cpplich[3], cpplich[4], cpplich[5]);
    cpplich = build_cpp_LICH(cppLSF, 5);
    qDebug("cppLICH for cppLSF 5: %02x %02x %02x %02x %02x %02x", cpplich[0], cpplich[1], cpplich[2], cpplich[3], cpplich[4], cpplich[5]);

    char clichOut[6];
    //qDebug("%02x %02x %02x %02x %02x %02x", lsfOut[0], lsfOut[1], lsfOut[2], lsfOut[3], lsfOut[4], lsfOut[5]);
    build_c_LICH(&clichOut[0], &lsfOut[0], 0);
    qDebug("clichOut 0:           %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 1);
    qDebug("clichOut 1:           %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 2);
    qDebug("clichOut 2:           %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 3);
    qDebug("clichOut 3:           %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 4);
    qDebug("clichOut 4:           %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );
    build_c_LICH(&clichOut[0], &lsfOut[0], 5);
    qDebug("clichOut 5:           %02x %02x %02x %02x %02x %02x ", (unsigned char)clichOut[0], (unsigned char)clichOut[1], (unsigned char)clichOut[2], (unsigned char)clichOut[3], (unsigned char)clichOut[4], (unsigned char)clichOut[5] );

    qDebug()<<"build_qstreamFrame:"<<build_qstreamFrame("AB4MW", "G4KLX", "12345678901234", "12345678901234").toHex(' ');

    std::vector<uint8_t> strframe = build_cpp_streamFrame("AB4MW", "G4KLX", "12345678901234", indata);
    qDebug()<<"build_cpp_streamFrame:"<<strframe<<strframe.size();

    qDebug()<<"strlen dcall:"<<strlen(dcall);
    qDebug()<<"strlen scall:"<<strlen(scall);
    char streamFrame[56];

    char cdata[15] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', 0};
    build_c_streamFrame(&streamFrame[0], &dcall[0], &scall[0], &cmeta[0], &cdata[0], strlen(cdata));
    qDebug("build_c_streamFrame: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ", \
    (unsigned char)streamFrame[0], (unsigned char)streamFrame[1], (unsigned char)streamFrame[2], (unsigned char)streamFrame[3], (unsigned char)streamFrame[4], (unsigned char)streamFrame[5], (unsigned char)streamFrame[6], (unsigned char)streamFrame[7], (unsigned char)streamFrame[8], (unsigned char)streamFrame[9], (unsigned char)streamFrame[10], (unsigned char)streamFrame[11], (unsigned char)streamFrame[12], (unsigned char)streamFrame[13], (unsigned char)streamFrame[14], (unsigned char)streamFrame[15]);
    qDebug("                     %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ", \
            (unsigned char)streamFrame[16], (unsigned char)streamFrame[17], (unsigned char)streamFrame[18], (unsigned char)streamFrame[19], (unsigned char)streamFrame[20], (unsigned char)streamFrame[21], (unsigned char)streamFrame[22], (unsigned char)streamFrame[23], (unsigned char)streamFrame[24], (unsigned char)streamFrame[25], (unsigned char)streamFrame[26], (unsigned char)streamFrame[27], (unsigned char)streamFrame[28], (unsigned char)streamFrame[29], (unsigned char)streamFrame[30], (unsigned char)streamFrame[31]);
    qDebug("                     %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x ", \
            (unsigned char)streamFrame[32], (unsigned char)streamFrame[33], (unsigned char)streamFrame[34], (unsigned char)streamFrame[35], (unsigned char)streamFrame[36], (unsigned char)streamFrame[37], (unsigned char)streamFrame[38], (unsigned char)streamFrame[39], (unsigned char)streamFrame[40], (unsigned char)streamFrame[41], (unsigned char)streamFrame[42], (unsigned char)streamFrame[43], (unsigned char)streamFrame[44], (unsigned char)streamFrame[45], (unsigned char)streamFrame[46], (unsigned char)streamFrame[47]);
    qDebug("                     %02x %02x %02x %02x %02x %02x %02x %02x", \
            (unsigned char)streamFrame[48], (unsigned char)streamFrame[49], (unsigned char)streamFrame[50], (unsigned char)streamFrame[51], (unsigned char)streamFrame[52], (unsigned char)streamFrame[53], (unsigned char)streamFrame[54], (unsigned char)streamFrame[55]);
    return 0;
}
