package com.lamonlind.appscan;

final class Ipv4Cidr {
    final long first;
    final long count;

    private Ipv4Cidr(long first, long count) {
        this.first = first;
        this.count = count;
    }

    static Ipv4Cidr parse(String input) {
        String[] parts = input.trim().split("/");
        if (parts.length != 2) throw new IllegalArgumentException("Invalid CIDR");

        long address = addressToLong(parts[0]);
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid CIDR");
        }
        if (prefix < 0 || prefix > 32) throw new IllegalArgumentException("Invalid CIDR");

        long hostBits = 32L - prefix;
        long blockSize = 1L << hostBits;
        long network = address & ((hostBits == 32) ? 0xffffffffL : (0xffffffffL << hostBits));
        network &= 0xffffffffL;

        long firstHost;
        long lastHost;
        if (prefix == 32) {
            firstHost = network;
            lastHost = network;
        } else if (prefix == 31) {
            firstHost = network;
            lastHost = network + blockSize - 1;
        } else {
            firstHost = network + 1;
            lastHost = network + blockSize - 2;
        }
        long count = lastHost - firstHost + 1;
        if (count < 0) count = 0;
        return new Ipv4Cidr(firstHost, count);
    }

    private static long addressToLong(String address) {
        String[] octets = address.split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("Invalid CIDR");
        long value = 0;
        for (String octet : octets) {
            int n;
            try {
                n = Integer.parseInt(octet);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid CIDR");
            }
            if (n < 0 || n > 255) throw new IllegalArgumentException("Invalid CIDR");
            value = (value << 8) | n;
        }
        return value & 0xffffffffL;
    }

    static String format(long value) {
        value &= 0xffffffffL;
        return ((value >>> 24) & 255) + "." +
                ((value >>> 16) & 255) + "." +
                ((value >>> 8) & 255) + "." +
                (value & 255);
    }
}
