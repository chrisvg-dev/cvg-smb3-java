package com.casystem.ka.test.samba;

public abstract class AbstractRemoteAccess {

    protected static final String LINE_SEPARATOR = System.getProperty("line.separator");
    protected static final int BUFFER_SIZE = 1 * 1024;

    public static final int CONNECT_TIMEOUT = 10000;
    public static final int READ_TIMEOUT = 60000;

    public abstract String read(String resource);
    public abstract byte[] readBinary(String resource);
    public abstract boolean write(String resource, String lines, String encoding);
    public abstract boolean write(String resource, byte[] lines);
    public abstract String[] list(String resource, String filter);
    public abstract boolean move(String resource, String sourcePath, String destinationPath);
    public abstract boolean delete(String resource);
}
