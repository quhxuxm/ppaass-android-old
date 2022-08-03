package com.ppaass.agent.service.handler.tcp;

import android.net.VpnService;
import android.util.Log;
import com.ppaass.agent.protocol.general.ip.*;
import com.ppaass.agent.protocol.general.tcp.TcpHeader;
import com.ppaass.agent.protocol.general.tcp.TcpPacket;
import com.ppaass.agent.protocol.general.tcp.TcpPacketReader;
import com.ppaass.agent.protocol.general.tcp.TcpPacketWriter;
import com.ppaass.agent.service.handler.TcpIpPacketWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class IpV4TcpPacketHandler implements TcpIpPacketWriter {
    private static final Random RANDOM = new Random();
    private final OutputStream rawDeviceOutputStream;
    private final HashMap<TcpConnectionRepositoryKey, TcpConnection> connectionRepository;
    private final VpnService vpnService;
    private final ExecutorService connectionThreadPool;
    private int ipIdentifier;

    public IpV4TcpPacketHandler(OutputStream rawDeviceOutputStream, VpnService vpnService) {
        this.rawDeviceOutputStream = rawDeviceOutputStream;
        this.vpnService = vpnService;
        this.connectionRepository = new HashMap<>();
        this.connectionThreadPool = Executors.newFixedThreadPool(128);
        this.ipIdentifier = RANDOM.nextInt(Short.MAX_VALUE * 2 + 2);
    }

    private TcpConnection retrieveTcpConnection(TcpConnectionRepositoryKey repositoryKey, TcpPacket tcpPacket)
            throws IOException {
        TcpConnection tcpConnection = this.connectionRepository.get(repositoryKey);
        if (tcpConnection != null) {
            Log.v(IpV4TcpPacketHandler.class.getName(),
                    ">>>>>>>> Get existing tcp connection: " + tcpConnection + ", tcp packet: " + tcpPacket);
            return tcpConnection;
        }
        synchronized (this.connectionRepository) {
            tcpConnection = new TcpConnection(repositoryKey, this, connectionRepository,
                    IpV4TcpPacketHandler.this.vpnService, 2000, 2000);
            tcpConnection.start();
            this.connectionRepository.put(repositoryKey, tcpConnection);
            this.connectionThreadPool.execute(tcpConnection);
            Log.d(IpV4TcpPacketHandler.class.getName(),
                    ">>>>>>>> Create tcp connection: " + tcpConnection + ", tcp packet: " + tcpPacket);
        }
        return tcpConnection;
    }

    private int generateChecksumToVerify(TcpPacket tcpPacket, IpV4Header ipV4Header) {
        ByteBuffer tcpPacketBuf = TcpPacketWriter.INSTANCE.write(tcpPacket, ipV4Header);
        byte[] tcpPacketBytes = new byte[tcpPacketBuf.remaining()];
        tcpPacketBuf.get(tcpPacketBytes);
        TcpPacket tcpPacketToVerify = TcpPacketReader.INSTANCE.parse(tcpPacketBytes);
        return tcpPacketToVerify.getHeader().getChecksum();
    }

    public void handle(TcpPacket tcpPacket, IpV4Header ipV4Header) throws Exception {
        int generatedChecksumToVerify = this.generateChecksumToVerify(tcpPacket, ipV4Header);
        if (generatedChecksumToVerify != tcpPacket.getHeader().getChecksum()) {
            Log.e(IpV4TcpPacketHandler.class.getName(),
                    ">>>>>>>> Fail to verify checksum for tcp packet: " + tcpPacket +
                            ", ip header: " +
                            ipV4Header + ", generated check sum: " + generatedChecksumToVerify +
                            ", incoming checksum: " + tcpPacket.getHeader().getChecksum());
            return;
        }
        TcpHeader tcpHeader = tcpPacket.getHeader();
        int sourcePort = tcpHeader.getSourcePort();
        int destinationPort = tcpHeader.getDestinationPort();
        byte[] sourceAddress = ipV4Header.getSourceAddress();
        byte[] destinationAddress = ipV4Header.getDestinationAddress();
        TcpConnectionRepositoryKey tcpConnectionRepositoryKey =
                new TcpConnectionRepositoryKey(sourcePort, destinationPort, sourceAddress, destinationAddress);
        TcpConnection tcpConnection = this.retrieveTcpConnection(tcpConnectionRepositoryKey, tcpPacket);
        Log.v(IpV4TcpPacketHandler.class.getName(),
                ">>>>>>>> Do inbound for tcp connection: " + tcpConnection + ", incoming tcp packet: " + tcpPacket +
                        ", ip header: " +
                        ipV4Header);
        tcpConnection.onDeviceInbound(tcpPacket);
    }

    @Override
    public void write(TcpConnection tcpConnection, TcpPacket tcpPacket) throws IOException {
        synchronized (this.rawDeviceOutputStream) {
            IpPacketBuilder ipPacketBuilder = new IpPacketBuilder();
            IpV4HeaderBuilder ipV4HeaderBuilder = new IpV4HeaderBuilder();
            int identification = this.ipIdentifier;
            this.ipIdentifier++;
            ipV4HeaderBuilder.identification(identification);
            ipV4HeaderBuilder.destinationAddress(tcpConnection.getRepositoryKey().getSourceAddress());
            ipV4HeaderBuilder.sourceAddress(tcpConnection.getRepositoryKey().getDestinationAddress());
            ipV4HeaderBuilder.protocol(IpDataProtocol.TCP);
            ipV4HeaderBuilder.ttl(64);
            ipV4HeaderBuilder.flags(new IpFlags(false, false));
            ipPacketBuilder.header(ipV4HeaderBuilder.build());
            ipPacketBuilder.data(tcpPacket);
            IpPacket ipPacket = ipPacketBuilder.build();
            ByteBuffer ipPacketBytes = IpPacketWriter.INSTANCE.write(ipPacket);
            Log.v(IpV4TcpPacketHandler.class.getName(),
                    "<<<<<<<< Write ip packet to device, current connection:  " + tcpConnection +
                            ", output ip packet: " + ipPacket);
            byte[] bytesWriteToDevice = new byte[ipPacketBytes.remaining()];
            ipPacketBytes.get(bytesWriteToDevice);
            ipPacketBytes.clear();
            this.rawDeviceOutputStream.write(bytesWriteToDevice);
            this.rawDeviceOutputStream.flush();
        }
    }
}
