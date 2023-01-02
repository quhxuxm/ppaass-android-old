package com.ppaass.agent.rust.protocol.general.udp;

import com.ppaass.agent.rust.protocol.general.ChecksumUtil;
import com.ppaass.agent.rust.protocol.general.ip.IpDataProtocol;
import com.ppaass.agent.rust.protocol.general.ip.IpV4Header;
import com.ppaass.agent.rust.protocol.general.ip.IpV6Header;

import java.nio.ByteBuffer;

public class UdpPacketWriter {
    public static final UdpPacketWriter INSTANCE = new UdpPacketWriter();

    private UdpPacketWriter() {
    }

    public ByteBuffer write(UdpPacket packet, IpV4Header ipHeader) {
        ByteBuffer fakeHeaderByteBuffer = ByteBuffer.allocate(12);
        fakeHeaderByteBuffer.put(ipHeader.getSourceAddress());
        fakeHeaderByteBuffer.put(ipHeader.getDestinationAddress());
        fakeHeaderByteBuffer.put((byte) 0);
        fakeHeaderByteBuffer.put((byte) IpDataProtocol.UDP.getValue());
        fakeHeaderByteBuffer.putShort((short) (packet.getHeader().getTotalLength()));
        fakeHeaderByteBuffer.flip();
        ByteBuffer byteBufferForChecksum =
                ByteBuffer.allocateDirect(packet.getHeader().getTotalLength() + 12);
        byteBufferForChecksum.put(fakeHeaderByteBuffer);
        ByteBuffer udpPacketBytesForChecksum = this.writeWithGivenChecksum(packet, 0);
        byteBufferForChecksum.put(udpPacketBytesForChecksum);
        byteBufferForChecksum.flip();
        int checksum = ChecksumUtil.INSTANCE.checksum(byteBufferForChecksum);
        return this.writeWithGivenChecksum(packet, checksum);
    }

    public byte[] write(UdpPacket packet, IpV6Header ipHeader) {
        throw new UnsupportedOperationException("Do not support IPv6");
    }

    private ByteBuffer writeWithGivenChecksum(UdpPacket packet, int checksum) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(packet.getHeader().getTotalLength());
        byteBuffer.putShort((short) packet.getHeader().getSourcePort());
        byteBuffer.putShort((short) packet.getHeader().getDestinationPort());
        byteBuffer.putShort((short) packet.getHeader().getTotalLength());
        byteBuffer.putShort((short) checksum);
        byteBuffer.put(packet.getData());
        byteBuffer.flip();
        return byteBuffer;
    }
}
