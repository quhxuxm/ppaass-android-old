package com.ppaass.agent.service;

public interface IVpnConst {
    int WRITE_BUFFER_SIZE = 65535;
    int READ_BUFFER_SIZE = 65535;
    int READ_REMOTE_BUFFER_SIZE = 65535;
    int MTU = 1500;
    short TCP_MSS = MTU - 40;
    int TCP_WINDOW = 65535;
    int UDP_HEADER_LENGTH = 8;

    String TCP_CONNECTION="TCP_CONNECTION";
    String UDP_SOURCE_ADDR="UDP_SOURCE_ADDR";
    String UDP_SOURCE_PORT="UDP_SOURCE_PORT";

}
