package com.ppaass.agent.service.handler.dns;

import java.net.InetAddress;
import java.util.List;
import java.util.Set;

public class DnsEntry {
    private String name;
    private List<InetAddress> addresses;
    private long lastAccessTime;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<InetAddress> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<InetAddress> addresses) {
        this.addresses = addresses;
    }

    public long getLastAccessTime() {
        return lastAccessTime;
    }

    public void setLastAccessTime(long lastAccessTime) {
        this.lastAccessTime = lastAccessTime;
    }
}
