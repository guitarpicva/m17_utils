//#include <QCoreApplication>
#include "m17_qt_utils.h"
#include "m17_c_utils.h"
#include "m17_cpp_utils.h"
//#include <stdlib.h>
#include <QDebug>

int main(int argc, char *argv[])
{
    const QByteArray addr("AB4MW");
    qDebug()<<"Encode AB4MW Qt:"<<m17_addr_qencode(addr);
    qDebug()<<"Encode AB4MW stdlib:"<<m17_addr_stdlib_encode(addr.toStdString());
    qDebug()<<"Encode AB4MW c:"<<m17_addr_cencode(addr.toStdString().c_str(), addr.length());

    char cdecoded[9];
    qDebug()<<"cdecoded array:"<<QString(cdecoded).toLatin1();
    m17_addr_cdecode(cdecoded, 59761681u);
    qDebug()<<"Decode AB4MW c:"<<cdecoded;

    qDebug()<<"Decode Qt EE:"<<m17_addr_qdecode(QByteArray::fromHex("EE6B28000000"));
    qDebug()<<"Decode Qt 0:"<<m17_addr_qdecode(QByteArray::fromHex("000000000000"));
    qDebug()<<"Decode Qt FF:"<<m17_addr_qdecode(QByteArray::fromHex("FFFFFFFFFFFF"));
    qDebug()<<"Decode Qt Encoded AB4MW:"<<m17_addr_qdecode(QByteArray::fromHex("0000038fe411"));
    qDebug()<<"Decode stdlib Encoded AB4MW (59761681):"<<m17_addr_stdlib_decode(59761681u).c_str();
    qDebug()<<"Decode stdlib Encoded EE:"<<m17_addr_stdlib_decode(262144000000000u).c_str();
    qDebug()<<"Decode stdlib Encoded 0 :"<<m17_addr_stdlib_decode(0).c_str();
    qDebug()<<"Decode stdlib Encoded FF:"<<m17_addr_stdlib_decode(18446744073709551615).c_str();

    qDebug()<<"qCRC for test frame (54412):"<<crc_ccitt_qbuild(QByteArray::fromHex("0000038fe411000003b5819fa0003132333435363738393031323334"));
    qDebug()<<"qCRC for 123456789:"<<crc_ccitt_qbuild(QString("123456789").toLatin1());
    qDebug()<<"qCRC for A:"<<crc_ccitt_qbuild(QString("A").toLatin1());
    qDebug()<<"qCRC for <empty>:"<<crc_ccitt_qbuild(QString("").toLatin1());

    qDebug()<<"cCRC for 123456789:"<<crc_ccitt_cbuild((unsigned char*)"123456789", 9);
    qDebug()<<"cCRC for A:"<<crc_ccitt_cbuild((unsigned char*)"A", 1);
    qDebug()<<"cCRC for <empty>:"<<crc_ccitt_cbuild((unsigned char*)"", 0);

    std::vector<uint8_t> in = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    qDebug()<<"cppCRC for 123456789:"<<crc_ccitt_cpp_build(in);
    //qDebug()<<"cppCRC for A:"<<crc_ccitt_cpp_build(std::string("A"));
    //qDebug()<<"cppCRC for <empty>:"<<crc_ccitt_cpp_build(std::string(""));

    const QByteArray LSF = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123";
    std::vector<uint8_t> cppLSF;
    foreach(const uint8_t c, LSF) {
        cppLSF.push_back(c);
    }
    qDebug()<<"LSF Qt test:"<<build_qLSF(m17_addr_qencode("AB4MW"), m17_addr_qencode("G4KLX"), "12345678901234").toHex();
    qDebug()<<"LSF stdlib test:"<<build_cpp_LSF(m17_addr_stdlib_encode("AB4MW"), m17_addr_stdlib_encode("G4KLX"), "12345678901234");

    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 0"<<build_qLICH(LSF, 0).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 1"<<build_qLICH(LSF, 1).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 2"<<build_qLICH(LSF, 2).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 3"<<build_qLICH(LSF, 3).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 4"<<build_qLICH(LSF, 4).toHex();
    qDebug()<<"qLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 5"<<build_qLICH(LSF, 5).toHex();

    qDebug()<<"cppLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 0"<<build_cpp_LICH(cppLSF, 0);
    qDebug()<<"cppLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 1"<<build_cpp_LICH(cppLSF, 1);
    qDebug()<<"cppLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 2"<<build_cpp_LICH(cppLSF, 2);
    qDebug()<<"cppLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 3"<<build_cpp_LICH(cppLSF, 3);
    qDebug()<<"cppLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 4"<<build_cpp_LICH(cppLSF, 4);
    qDebug()<<"cppLICH for ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 5"<<build_cpp_LICH(cppLSF, 5);

    qDebug()<<"build_qstreamFrame:"<<build_qstreamFrame("AB4MW", "G4KLX", "12345678901234", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456").toHex();
    std::vector<uint8_t> strframe = build_cpp_streamFrame("AB4MW", "G4KLX", "12345678901234", in);
    qDebug()<<"build_cpp_streamFrame:"<<strframe<<strframe.size();
    return 0;
}
