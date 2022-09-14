package com.ppaass.agent.service.handler.tcp;

import android.net.VpnService;
import android.util.Log;
import com.ppaass.agent.protocol.general.ip.*;
import com.ppaass.agent.protocol.general.tcp.*;
import com.ppaass.agent.service.IVpnConst;
import com.ppaass.agent.service.handler.ITcpIpPacketWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class IpV4TcpConnectionManager implements ITcpIpPacketWriter, ITcpConnectionManager {
    private static final Random RANDOM = new Random();
    private static final AtomicInteger TIMESTAMP = new AtomicInteger();
    private final FileOutputStream rawDeviceOutputStream;
    private final Map<TcpConnectionRepositoryKey, TcpConnectionWrapper> connectionRepository;
    private final VpnService vpnService;
    private final ExecutorService connectionThreadPool;
    private final AtomicInteger ipIdentifier;

    private static class TcpConnectionWrapper {
        TcpConnection connection;
        Future<?> connectionTask;

        @Override
        public String toString() {
            return "TcpConnectionWrapper{" +
                    "connection=" + connection +
                    ", connectionTask=" + connectionTask +
                    '}';
        }
    }

    public IpV4TcpConnectionManager(FileOutputStream rawDeviceOutputStream, VpnService vpnService) {
        this.rawDeviceOutputStream = rawDeviceOutputStream;
        this.vpnService = vpnService;
        this.connectionRepository = new ConcurrentHashMap<>();
        this.connectionThreadPool = Executors.newWorkStealingPool(IVpnConst.TCP_CONNECTION_NUMBER);
        this.ipIdentifier = new AtomicInteger(RANDOM.nextInt(Short.MAX_VALUE * 2 + 2));
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(() -> {
            this.connectionRepository.forEach((tcpConnectionRepositoryKey, tcpConnectionWrapper) -> {
                TcpConnection tcpConnection = tcpConnectionWrapper.connection;
                long connectionIdleTime = tcpConnection.getLatestActiveTime() - System.currentTimeMillis();
                if (connectionIdleTime > IVpnConst.TCP_CONNECTION_IDLE_TIMEOUT_MS) {
                    this.unregisterConnection(tcpConnectionRepositoryKey);
                }
            });
        }, 0, 10, TimeUnit.SECONDS);
    }

    private TcpConnectionWrapper prepareTcpConnection(TcpConnectionRepositoryKey repositoryKey, TcpPacket tcpPacket) {
        synchronized (this.connectionRepository) {
            var result = this.connectionRepository.get(repositoryKey);
            if (result != null) {
                return result;
            }
            result = new TcpConnectionWrapper();
            result.connection = new TcpConnection(repositoryKey,
                    this,
                    this.vpnService);
            this.connectionRepository.put(repositoryKey, result);
            result.connectionTask = this.connectionThreadPool.submit(result.connection);
            Log.d(IpV4TcpConnectionManager.class.getName(),
                    ">>>>>>>> Create tcp connection: " + result + ", tcp packet: " + tcpPacket +
                            ", connection repository size: " + this.connectionRepository.size() +
                            ", connection thread pool: " + this.connectionThreadPool);
            return result;
        }
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
            Log.e(IpV4TcpConnectionManager.class.getName(),
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
        TcpConnectionWrapper tcpConnectionWrapper = this.prepareTcpConnection(tcpConnectionRepositoryKey, tcpPacket);
        TcpConnection tcpConnection = tcpConnectionWrapper.connection;
        tcpConnection.onDeviceInbound(tcpPacket);
        Log.v(IpV4TcpConnectionManager.class.getName(),
                ">>>>>>>> Do inbound for tcp connection: " + tcpConnection + ", incoming tcp packet: " + tcpPacket +
                        ", ip header: " +
                        ipV4Header + ", tcp connection repository size: " +
                        this.connectionRepository.size());
    }

    @Override
    public void unregisterConnection(TcpConnectionRepositoryKey key) {
        synchronized (this) {
            TcpConnectionWrapper tcpConnectionWrapper = this.connectionRepository.remove(key);
            if (tcpConnectionWrapper == null) {
                return;
            }
            tcpConnectionWrapper.connection.getStatus().set(TcpConnectionStatus.CLOSED);
            tcpConnectionWrapper.connection.clearResource();
            tcpConnectionWrapper.connectionTask.cancel(true);
        }
    }

    public void writeSyncAckToDevice(TcpConnection connection, long sequenceNumber, long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        tcpPacketBuilder.syn(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        ByteBuffer mssByteBuffer = ByteBuffer.allocate(2);
        mssByteBuffer.putShort((short) (IVpnConst.TCP_MSS & 0xFFFF));
        tcpPacketBuilder.addOption(new TcpHeaderOption(TcpHeaderOption.Kind.MSS, mssByteBuffer.array()));
        tcpPacketBuilder.addOption(new TcpHeaderOption(TcpHeaderOption.Kind.SACK_PREMITTED, null));
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write sync ack tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeAckToDevice(byte[] ackData, TcpConnection connection, long sequenceNumber,
                                 long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        if (ackData != null) {
            tcpPacketBuilder.psh(true);
        }
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        tcpPacketBuilder.data(ackData);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write ack tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeRstAckToDevice(TcpConnection connection, long sequenceNumber,
                                    long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        tcpPacketBuilder.rst(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write rst tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeRstToDevice(TcpConnection connection, long sequenceNumber,
                                 long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.rst(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write rst tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeFinAckToDevice(byte[] data, TcpConnection connection, long sequenceNumber,
                                    long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        tcpPacketBuilder.fin(true);
        if (data != null) {
            tcpPacketBuilder.psh(true);
        }
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write fin ack tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeFinToDevice(TcpConnection connection, long sequenceNumber,
                                 long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.fin(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write fin tcp packet to device outbound queue because of error.", e);
        }
    }

    private TcpPacket buildCommonTcpPacket(TcpPacketBuilder tcpPacketBuilder, TcpConnection connection,
                                           long sequenceNumber,
                                           long acknowledgementNumber) {
        tcpPacketBuilder.destinationPort(connection.getRepositoryKey().getSourcePort());
        tcpPacketBuilder.sourcePort(connection.getRepositoryKey().getDestinationPort());
        tcpPacketBuilder.sequenceNumber(sequenceNumber);
        tcpPacketBuilder.acknowledgementNumber(acknowledgementNumber);
        return tcpPacketBuilder.build();
    }

    private void write(TcpConnection tcpConnection, TcpPacket tcpPacket) throws IOException {
        IpPacketBuilder ipPacketBuilder = new IpPacketBuilder();
        IpV4HeaderBuilder ipV4HeaderBuilder = new IpV4HeaderBuilder();
        ipV4HeaderBuilder.identification(this.ipIdentifier.incrementAndGet());
        ipV4HeaderBuilder.destinationAddress(tcpConnection.getRepositoryKey().getSourceAddress());
        ipV4HeaderBuilder.sourceAddress(tcpConnection.getRepositoryKey().getDestinationAddress());
        ipV4HeaderBuilder.protocol(IpDataProtocol.TCP);
        ipV4HeaderBuilder.ttl(128);
        ipV4HeaderBuilder.flags(new IpFlags(true, false));
        ipPacketBuilder.header(ipV4HeaderBuilder.build());
        ipPacketBuilder.data(tcpPacket);
        IpPacket ipPacket = ipPacketBuilder.build();
        ByteBuffer ipPacketBytes = IpPacketWriter.INSTANCE.write(ipPacket);
        Log.v(IpV4TcpConnectionManager.class.getName(),
                "<<<<<<<< Write ip packet to device, current connection:  " + tcpConnection +
                        ", output ip packet: " + ipPacket);
        byte[] bytesWriteToDevice = new byte[ipPacketBytes.remaining()];
        ipPacketBytes.get(bytesWriteToDevice);
        ipPacketBytes.clear();
//        synchronized (this.rawDeviceOutputStream) {
            this.rawDeviceOutputStream.write(bytesWriteToDevice);
            this.rawDeviceOutputStream.flush();
//        }
    }
}
