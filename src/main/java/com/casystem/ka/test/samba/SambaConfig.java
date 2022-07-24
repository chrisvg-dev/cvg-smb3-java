package com.casystem.ka.test.samba;

import java.io.Serializable;

public class SambaConfig implements Serializable {
    private static final long serialVersionUID = 1L;
    private String host;
    private String user;
    private String password;
    private String path;
    private String domain;
    private String share;
    private String filePath;

    public SambaConfig() {
    }

    public String getHost() {
        return host;
    }
    public void setHost(String host) {
        this.host = host;
    }
    public String getUser() {
        return user;
    }
    public void setUser(String user) {
        this.user = user;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getPath() {
        return path;
    }
    public void setPath(String path) {
        this.path = path;
    }
    public String getDomain() {
        return domain;
    }
    public void setDomain(String domain) {
        this.domain = domain;
    }
    public String getShare() {
        return share;
    }
    public void setShare(String share) {
        this.share = share;
    }
    public String getFilePath() {
        return filePath;
    }
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    @Override
    public String toString() {
        return "SambaBO{" +
                "host='" + host + '\'' +
                ", user='" + user + '\'' +
                ", pass='" + password + '\'' +
                ", path='" + path + '\'' +
                ", domain='" + domain + '\'' +
                ", share='" + share + '\'' +
                ", filePath='" + filePath + '\'' +
                '}';
    }
}
