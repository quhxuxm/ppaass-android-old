package com.ppaass.agent.protocol.message;

public enum ProxyMessagePayloadType {
    TcpConnectSuccess((byte)210),
    TcpConnectFail((byte)211),
    TcpData((byte)212),
    UdpAssociateSuccess((byte)221),
    UdpAssociateFail((byte)222),
    UdpData((byte)224),
    UdpDataComplete((byte)225),
    UdpDataRelayFail((byte)223),
    HeartbeatSuccess((byte)230);
    private final byte value;

    ProxyMessagePayloadType(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static ProxyMessagePayloadType from(byte value) {
        if (TcpConnectSuccess.getValue() == value) {
            return TcpConnectSuccess;
        }
        if (TcpConnectFail.getValue() == value) {
            return TcpConnectFail;
        }
        if (TcpData.getValue() == value) {
            return TcpData;
        }
        if (UdpAssociateSuccess.getValue() == value) {
            return UdpAssociateSuccess;
        }
        if (UdpAssociateFail.getValue() == value) {
            return UdpAssociateFail;
        }
        if (UdpData.getValue() == value) {
            return UdpData;
        }
        if (UdpDataComplete.getValue() == value) {
            return UdpDataComplete;
        }
        if (UdpDataRelayFail.getValue() == value) {
            return UdpDataRelayFail;
        }
        if (HeartbeatSuccess.getValue() == value) {
            return HeartbeatSuccess;
        }
        throw new UnsupportedOperationException();
    }
}
