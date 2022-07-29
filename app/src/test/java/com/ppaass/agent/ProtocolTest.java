package com.ppaass.agent;

import com.ppaass.agent.protocol.general.ip.*;
import com.ppaass.agent.protocol.general.tcp.TcpPacket;
import com.ppaass.agent.protocol.general.tcp.TcpPacketBuilder;
import org.junit.Test;

import java.util.Arrays;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ProtocolTest {
    @Test
    public void testTcp() {
//        short[] ipData = new short[]{
//                0x45, 0x00
//                , 0x05, 0x41, 0xb1, 0x4e, 0x40, 0x00, 0x3f, 0x06, 0xca, 0xb4, 0x0a, 0xde, 0xa0, 0x4b, 0x0a, 0xaf
//                , 0x04, 0xdc, 0x00, 0x50, 0xec, 0x2c, 0x56, 0x89, 0xe6, 0xde, 0x50, 0xb1, 0xb7, 0xd2, 0x50, 0x18
//                , 0x0f, 0x7d, 0x1b, 0x5e, 0x00, 0x00, 0x72, 0x2e, 0x67, 0x69, 0x66, 0x22, 0x20, 0x61, 0x6c, 0x74
//                , 0x3d, 0x22, 0x5b, 0x44, 0x49, 0x52, 0x5d, 0x22, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74
//                , 0x64, 0x3e, 0x3c, 0x61, 0x20, 0x68, 0x72, 0x65, 0x66, 0x3d, 0x22, 0x6c, 0x6f, 0x67, 0x73, 0x2f
//                , 0x22, 0x3e, 0x6c, 0x6f, 0x67, 0x73, 0x2f, 0x3c, 0x2f, 0x61, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e
//                , 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68, 0x74
//                , 0x22, 0x3e, 0x31, 0x38, 0x2d, 0x4a, 0x61, 0x6e, 0x2d, 0x32, 0x30, 0x31, 0x39, 0x20, 0x31, 0x36
//                , 0x3a, 0x31, 0x34, 0x20, 0x20, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c
//                , 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x20, 0x20, 0x2d, 0x20
//                , 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x3e, 0x26, 0x6e, 0x62, 0x73, 0x70, 0x3b, 0x3c
//                , 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x2f, 0x74, 0x72, 0x3e, 0x0a, 0x3c, 0x74, 0x72, 0x3e, 0x3c, 0x74
//                , 0x64, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x74, 0x6f, 0x70, 0x22, 0x3e, 0x3c
//                , 0x69, 0x6d, 0x67, 0x20, 0x73, 0x72, 0x63, 0x3d, 0x22, 0x2f, 0x69, 0x63, 0x6f, 0x6e, 0x73, 0x2f
//                , 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x2e, 0x67, 0x69, 0x66, 0x22, 0x20, 0x61, 0x6c, 0x74
//                , 0x3d, 0x22, 0x5b, 0x20, 0x20, 0x20, 0x5d, 0x22, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74
//                , 0x64, 0x3e, 0x3c, 0x61, 0x20, 0x68, 0x72, 0x65, 0x66, 0x3d, 0x22, 0x6c, 0x6f, 0x67, 0x73, 0x79
//                , 0x6e, 0x63, 0x2e, 0x6c, 0x6f, 0x22, 0x3e, 0x6c, 0x6f, 0x67, 0x73, 0x79, 0x6e, 0x63, 0x2e, 0x6c
//                , 0x6f, 0x3c, 0x2f, 0x61, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c
//                , 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x31, 0x39, 0x2d, 0x41
//                , 0x75, 0x67, 0x2d, 0x32, 0x30, 0x32, 0x30, 0x20, 0x30, 0x33, 0x3a, 0x31, 0x37, 0x20, 0x20, 0x3c
//                , 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72
//                , 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x36, 0x2e, 0x32, 0x4b, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c
//                , 0x74, 0x64, 0x3e, 0x26, 0x6e, 0x62, 0x73, 0x70, 0x3b, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x2f
//                , 0x74, 0x72, 0x3e, 0x0a, 0x3c, 0x74, 0x72, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x76, 0x61, 0x6c, 0x69
//                , 0x67, 0x6e, 0x3d, 0x22, 0x74, 0x6f, 0x70, 0x22, 0x3e, 0x3c, 0x69, 0x6d, 0x67, 0x20, 0x73, 0x72
//                , 0x63, 0x3d, 0x22, 0x2f, 0x69, 0x63, 0x6f, 0x6e, 0x73, 0x2f, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77
//                , 0x6e, 0x2e, 0x67, 0x69, 0x66, 0x22, 0x20, 0x61, 0x6c, 0x74, 0x3d, 0x22, 0x5b, 0x20, 0x20, 0x20
//                , 0x5d, 0x22, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x3e, 0x3c, 0x61, 0x20, 0x68
//                , 0x72, 0x65, 0x66, 0x3d, 0x22, 0x6c, 0x6f, 0x67, 0x73, 0x79, 0x6e, 0x63, 0x2e, 0x6c, 0x6f, 0x67
//                , 0x22, 0x3e, 0x6c, 0x6f, 0x67, 0x73, 0x79, 0x6e, 0x63, 0x2e, 0x6c, 0x6f, 0x67, 0x3c, 0x2f, 0x61
//                , 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d
//                , 0x22, 0x72, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x31, 0x37, 0x2d, 0x44, 0x65, 0x63, 0x2d, 0x32
//                , 0x30, 0x32, 0x30, 0x20, 0x30, 0x37, 0x3a, 0x32, 0x38, 0x20, 0x20, 0x3c, 0x2f, 0x74, 0x64, 0x3e
//                , 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68, 0x74
//                , 0x22, 0x3e, 0x34, 0x30, 0x37, 0x4d, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x3e, 0x26
//                , 0x6e, 0x62, 0x73, 0x70, 0x3b, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x2f, 0x74, 0x72, 0x3e, 0x0a
//                , 0x3c, 0x74, 0x72, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22
//                , 0x74, 0x6f, 0x70, 0x22, 0x3e, 0x3c, 0x69, 0x6d, 0x67, 0x20, 0x73, 0x72, 0x63, 0x3d, 0x22, 0x2f
//                , 0x69, 0x63, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x2e, 0x67, 0x69, 0x66
//                , 0x22, 0x20, 0x61, 0x6c, 0x74, 0x3d, 0x22, 0x5b, 0x44, 0x49, 0x52, 0x5d, 0x22, 0x3e, 0x3c, 0x2f
//                , 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x3e, 0x3c, 0x61, 0x20, 0x68, 0x72, 0x65, 0x66, 0x3d, 0x22
//                , 0x6c, 0x6f, 0x73, 0x74, 0x2b, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x2f, 0x22, 0x3e, 0x6c, 0x6f, 0x73
//                , 0x74, 0x2b, 0x66, 0x6f, 0x75, 0x6e, 0x64, 0x2f, 0x3c, 0x2f, 0x61, 0x3e, 0x3c, 0x2f, 0x74, 0x64
//                , 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68
//                , 0x74, 0x22, 0x3e, 0x31, 0x35, 0x2d, 0x4a, 0x61, 0x6e, 0x2d, 0x32, 0x30, 0x31, 0x35, 0x20, 0x32
//                , 0x32, 0x3a, 0x34, 0x37, 0x20, 0x20, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61
//                , 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x20, 0x20, 0x2d
//                , 0x20, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x3e, 0x26, 0x6e, 0x62, 0x73, 0x70, 0x3b
//                , 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x2f, 0x74, 0x72, 0x3e, 0x0a, 0x3c, 0x74, 0x72, 0x3e, 0x3c
//                , 0x74, 0x64, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x74, 0x6f, 0x70, 0x22, 0x3e
//                , 0x3c, 0x69, 0x6d, 0x67, 0x20, 0x73, 0x72, 0x63, 0x3d, 0x22, 0x2f, 0x69, 0x63, 0x6f, 0x6e, 0x73
//                , 0x2f, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x2e, 0x67, 0x69, 0x66, 0x22, 0x20, 0x61, 0x6c, 0x74
//                , 0x3d, 0x22, 0x5b, 0x44, 0x49, 0x52, 0x5d, 0x22, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74
//                , 0x64, 0x3e, 0x3c, 0x61, 0x20, 0x68, 0x72, 0x65, 0x66, 0x3d, 0x22, 0x70, 0x65, 0x72, 0x66, 0x6c
//                , 0x6f, 0x67, 0x73, 0x2f, 0x22, 0x3e, 0x70, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x67, 0x73, 0x2f, 0x3c
//                , 0x2f, 0x61, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67
//                , 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x30, 0x36, 0x2d, 0x4e, 0x6f, 0x76
//                , 0x2d, 0x32, 0x30, 0x32, 0x30, 0x20, 0x30, 0x39, 0x3a, 0x33, 0x32, 0x20, 0x20, 0x3c, 0x2f, 0x74
//                , 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67
//                , 0x68, 0x74, 0x22, 0x3e, 0x20, 0x20, 0x2d, 0x20, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64
//                , 0x3e, 0x26, 0x6e, 0x62, 0x73, 0x70, 0x3b, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x2f, 0x74, 0x72
//                , 0x3e, 0x0a, 0x3c, 0x74, 0x72, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x67, 0x6e
//                , 0x3d, 0x22, 0x74, 0x6f, 0x70, 0x22, 0x3e, 0x3c, 0x69, 0x6d, 0x67, 0x20, 0x73, 0x72, 0x63, 0x3d
//                , 0x22, 0x2f, 0x69, 0x63, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x2e, 0x67
//                , 0x69, 0x66, 0x22, 0x20, 0x61, 0x6c, 0x74, 0x3d, 0x22, 0x5b, 0x44, 0x49, 0x52, 0x5d, 0x22, 0x3e
//                , 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x3e, 0x3c, 0x61, 0x20, 0x68, 0x72, 0x65, 0x66
//                , 0x3d, 0x22, 0x73, 0x79, 0x73, 0x6c, 0x6f, 0x67, 0x2f, 0x22, 0x3e, 0x73, 0x79, 0x73, 0x6c, 0x6f
//                , 0x67, 0x2f, 0x3c, 0x2f, 0x61, 0x3e, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61
//                , 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22, 0x72, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x31, 0x36, 0x2d
//                , 0x4a, 0x75, 0x6e, 0x2d, 0x32, 0x30, 0x31, 0x35, 0x20, 0x31, 0x37, 0x3a, 0x33, 0x35, 0x20, 0x20
//                , 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c, 0x74, 0x64, 0x20, 0x61, 0x6c, 0x69, 0x67, 0x6e, 0x3d, 0x22
//                , 0x72, 0x69, 0x67, 0x68, 0x74, 0x22, 0x3e, 0x20, 0x20, 0x2d, 0x20, 0x3c, 0x2f, 0x74, 0x64, 0x3e
//                , 0x3c, 0x74, 0x64, 0x3e, 0x26, 0x6e, 0x62, 0x73, 0x70, 0x3b, 0x3c, 0x2f, 0x74, 0x64, 0x3e, 0x3c
//                , 0x2f, 0x74, 0x72, 0x3e, 0x0a, 0x3c, 0x74, 0x72, 0x3e, 0x3c, 0x74, 0x68, 0x20, 0x63, 0x6f, 0x6c
//                , 0x73, 0x70, 0x61, 0x6e, 0x3d, 0x22, 0x35, 0x22, 0x3e, 0x3c, 0x68, 0x72, 0x3e, 0x3c, 0x2f, 0x74
//                , 0x68, 0x3e, 0x3c, 0x2f, 0x74, 0x72, 0x3e, 0x0a, 0x3c, 0x2f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x3e
//                , 0x0a, 0x3c, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x3e, 0x41, 0x70, 0x61, 0x63, 0x68, 0x65
//                , 0x2f, 0x32, 0x2e, 0x32, 0x2e, 0x31, 0x35, 0x20, 0x28, 0x43, 0x65, 0x6e, 0x74, 0x4f, 0x53, 0x29
//                , 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x61, 0x74, 0x20, 0x73, 0x66, 0x2d, 0x70, 0x72
//                , 0x6f, 0x64, 0x2d, 0x61, 0x72, 0x63, 0x68, 0x30, 0x31, 0x2e, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x77
//                , 0x61, 0x67, 0x65, 0x72, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x50, 0x6f
//                , 0x72, 0x74, 0x20, 0x38, 0x30, 0x3c, 0x2f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x3e, 0x0a
//                , 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x0a
//        };
        short[] ipData = new short[]{
                0x45, 0x00, 0x00, 0x34, 0x3f, 0xb8, 0x40, 0x00, 0x7d, 0x06, 0x23, 0x76, 0x0a, 0xf6, 0x80, 0x15, 0x0a,
                0xaf, 0x04, 0xdc, 0x00, 0x35, 0xe7, 0x0c, 0x38, 0xae, 0xa6, 0xd3, 0xe6, 0xe8, 0x31, 0xd6, 0x80, 0x12,
                0x20, 0x00, 0xd4, 0xe7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04,
                0x02
        };
        byte[] ipDataByteArray = new byte[ipData.length];
        for (int i = 0; i < ipData.length; i++) {
            ipDataByteArray[i] = (byte) ipData[i];
        }
        IpPacket ipPacket = IpPacketReader.INSTANCE.parse(ipDataByteArray);
        System.out.println(ipPacket);
        System.out.println("======================================");
        byte[] ipPacketArray = IpPacketWriter.INSTANCE.write(ipPacket);
        short[] ipPacketArrayInShort = new short[ipPacketArray.length];
        for (int i = 0; i < ipPacketArray.length; i++) {
            ipPacketArrayInShort[i] = (short) (ipPacketArray[i] & 0xFF);
        }
        String[] hexArray = new String[ipPacketArrayInShort.length];
        for (int i = 0; i < ipPacketArrayInShort.length; i++) {
            hexArray[i] = Integer.toHexString(ipPacketArrayInShort[i]);
        }
        System.out.println(Arrays.toString(hexArray));
        System.out.println("======================================");
        IpPacketBuilder ipPacketBuilder = new IpPacketBuilder();
        IpV4HeaderBuilder ipV4HeaderBuilder = new IpV4HeaderBuilder();
        IpV4Header originalIpV4Header = (IpV4Header) ipPacket.getHeader();
        TcpPacket originalTcpPacket = (TcpPacket) ipPacket.getData();
        ipV4HeaderBuilder.protocol(originalIpV4Header.getProtocol())
                .destinationAddress(originalIpV4Header.getDestinationAddress())
                .sourceAddress(originalIpV4Header.getSourceAddress()).ds(originalIpV4Header.getDs())
                .ecn(originalIpV4Header.getEcn()).flags(originalIpV4Header.getFlags())
                .fragmentOffset(originalIpV4Header.getFragmentOffset())
                .identification(originalIpV4Header.getIdentification()).ttl(originalIpV4Header.getTtl())
                .options(originalIpV4Header.getOptions());
        ipPacketBuilder.header(ipV4HeaderBuilder.build());
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(originalTcpPacket.getHeader().isAck()).psh(originalTcpPacket.getHeader().isPsh())
                .rst(originalTcpPacket.getHeader().isRst()).fin(originalTcpPacket.getHeader().isFin())
                .syn(originalTcpPacket.getHeader().isSyn()).urg(originalTcpPacket.getHeader().isUrg())
                .acknowledgementNumber(originalTcpPacket.getHeader().getAcknowledgementNumber())
                .sequenceNumber(originalTcpPacket.getHeader().getSequenceNumber())
                .destinationPort(originalTcpPacket.getHeader().getDestinationPort())
                .sourcePort(originalTcpPacket.getHeader().getSourcePort())
                .window(originalTcpPacket.getHeader().getWindow()).resolve(originalTcpPacket.getHeader().getResolve())
                .urgPointer(originalTcpPacket.getHeader().getUrgPointer()).data(originalTcpPacket.getData());
        originalTcpPacket.getHeader().getOptions().forEach(tcpPacketBuilder::addOption);
        ipPacketBuilder.data(tcpPacketBuilder.build());
        IpPacket newIpPacket = ipPacketBuilder.build();
        byte[] newIpPacketArray = IpPacketWriter.INSTANCE.write(newIpPacket);
        short[] newIpPacketArrayInShort = new short[newIpPacketArray.length];
        for (int i = 0; i < newIpPacketArray.length; i++) {
            newIpPacketArrayInShort[i] = (short) (newIpPacketArray[i] & 0xFF);
        }
        String[] newHexArray = new String[newIpPacketArrayInShort.length];
        for (int i = 0; i < newIpPacketArrayInShort.length; i++) {
            newHexArray[i] = Integer.toHexString(newIpPacketArrayInShort[i]);
        }
        System.out.println(newIpPacket);
        System.out.println("======================================");
        System.out.println(Arrays.toString(newHexArray));
    }

    public static void testUdp() {
        short[] ipData = new short[]{
                0x45, 0x00
                , 0x00, 0x64, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x7b, 0x2c, 0xc0, 0xa8, 0x1f, 0x01, 0xc0, 0xa8
                , 0x1f, 0x0b, 0x00, 0x35, 0xdc, 0xaf, 0x00, 0x50, 0x09, 0x84, 0xbe, 0x43, 0x81, 0x80, 0x00, 0x01
                , 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x68, 0x6d, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03
                , 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00
                , 0x00, 0x1e, 0x00, 0x0e, 0x02, 0x68, 0x6d, 0x01, 0x65, 0x06, 0x73, 0x68, 0x69, 0x66, 0x65, 0x6e
                , 0xc0, 0x15, 0xc0, 0x2a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0x6f, 0xce
                , 0xd1, 0xf9
        };
        byte[] ipDataByteArray = new byte[ipData.length];
        for (int i = 0; i < ipData.length; i++) {
            ipDataByteArray[i] = (byte) ipData[i];
        }
        IpPacket ipPacket = IpPacketReader.INSTANCE.parse(ipDataByteArray);
        System.out.println(ipPacket);
        System.out.println("======================================");
        byte[] ipPacketArray = IpPacketWriter.INSTANCE.write(ipPacket);
        short[] ipPacketArrayInShort = new short[ipPacketArray.length];
        for (int i = 0; i < ipPacketArray.length; i++) {
            ipPacketArrayInShort[i] = (short) (ipPacketArray[i] & 0xFF);
        }
        String[] hexArray = new String[ipPacketArrayInShort.length];
        for (int i = 0; i < ipPacketArrayInShort.length; i++) {
            hexArray[i] = Integer.toHexString(ipPacketArrayInShort[i]);
        }
        System.out.println(Arrays.toString(hexArray));
    }
}
