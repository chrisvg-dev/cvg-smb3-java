package com.casystem.ka.test.samba;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;

import java.io.*;
import java.util.EnumSet;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class SmbRemoteAccess extends AbstractRemoteAccess {
    private static final Logger LOG = Logger.getLogger(SmbRemoteAccess.class.getName());
    private static final String URL = "smb://cristian:a28d8896f9@192.168.221.129$samba-share";
    public SmbRemoteAccess() {}

    private static String[] URLSplit(String url){
        String newURL = url.replaceAll("smb://", "");
        return newURL.split("[:|@|$]");
    }

    public static void main(String[] args) {
        LOG.info( new SmbRemoteAccess().list("", "UTF8").length + "" );
//       new SmbRemoteAccess().list("", "UTF8") ;
    }

    private static AuthenticationContext getAuthentication() {
        return new AuthenticationContext("cristian", "a28d8896f9".toCharArray(), "192.168.221.129");
    }

    @Override
    public String read(String resource) {
        String result = "";
        try {
            String[] params = URLSplit(URL);
            SMBClient client = new SMBClient();
            Connection connection = client.connect("192.168.221.129");
            AuthenticationContext ac = getAuthentication();
            Session session = connection.authenticate(ac);

            DiskShare share = (DiskShare) session.connectShare("samba-share");
            if ( !share.fileExists(resource) ) {
                LOG.info("Archivo no encontrado");
                return null;
            }

            File file = share.openFile(resource,
                    EnumSet.of(AccessMask.FILE_READ_DATA),
                    null,
                    SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN,
                    null);

            String cadena;
            BufferedReader b = new BufferedReader(new InputStreamReader(file.getInputStream()));
            while((cadena = b.readLine()) != null) {
                result += cadena + "\n";
            }
            file.close();
            b.close();

            return result;
        } catch (Exception e){
            LOG.info(e.getMessage());
            return null;
        }
    }

    @Override
    public byte[] readBinary(String resource) {
        return new byte[0];
    }

    @Override
    public boolean write(String resource, String lines, String encoding) {
        try {
            SMBClient client = new SMBClient();
            try (Connection connection = client.connect("192.168.221.129")) {
                AuthenticationContext ac = getAuthentication();
                Session session = connection.authenticate(ac);

                DiskShare share = (DiskShare) session.connectShare("samba-share");
                File file = share.openFile(resource,
                        EnumSet.of(AccessMask.FILE_APPEND_DATA),
                        EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                        SMB2ShareAccess.ALL,
                        null,
                        EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

                byte[] lineBytes = lines.getBytes();
                OutputStream os = file.getOutputStream();
                os.write(lineBytes);
                os.flush();
                os.close();

                share.close();
                file.close();
            }
        } catch (Exception e){
            LOG.info(e.getMessage());
        }
        return false;
    }

    @Override
    public boolean write(String resource, byte[] lines) {
        return false;
    }

    @Override
    public String[] list(String resource, String filter) {
        SMBClient client = new SMBClient();
        try (Connection connection = client.connect("192.168.221.129")) {
            AuthenticationContext ac = getAuthentication();
            Session session = connection.authenticate(ac);

            // Connect to Share
            DiskShare share = (DiskShare) session.connectShare("samba-share");
            String filterFormat = "*."+filter;

            return (String[]) share.list(resource, filterFormat).stream()
                    .map( item ->  item.getFileName())
                    .toArray();

        } catch (Exception e) {
            LOG.info(e.getMessage());
        }
        return new String[0];
    }

    @Override
    public boolean move(String resource, String sourcePath, String destinationPath)  {
        SMBClient client = new SMBClient();
        try (Connection connection = client.connect("192.168.221.129")) {
            AuthenticationContext ac = getAuthentication();
            Session session = connection.authenticate(ac);

            DiskShare share = (DiskShare) session.connectShare("samba-share");

            String sourceFile = sourcePath + "/" + resource;
            File oldFile = share.openFile(
                    sourceFile,
                    EnumSet.of(AccessMask.FILE_READ_DATA),null,
                    SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN,
                    EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

            if (!share.folderExists(destinationPath)) share.mkdir(destinationPath);

            String destinationFile = destinationPath + "/destination.txt";
            File newFile = share.openFile(destinationFile,
                    EnumSet.of(AccessMask.FILE_WRITE_DATA),
                    null,
                    SMB2ShareAccess.ALL,
                    null,
                    null);
            copyFile(oldFile, newFile);

            boolean fileExists = share.fileExists(destinationFile);
            if (fileExists) {
                share.rm(resource);
                oldFile.close();
                newFile.close();
                share.close();
            }
            return fileExists;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void copyFile(File source, File destination) throws IOException {
        byte[] buffer = new byte[8000];
        try(InputStream in = source.getInputStream()) {
            try(OutputStream out = destination.getOutputStream()) {
                int bytesRead;
                while((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    @Override
    public boolean delete(String resource) {
        SMBClient client = new SMBClient();

        try (Connection connection = client.connect("192.168.221.129")) {
            AuthenticationContext ac = getAuthentication();
            Session session = connection.authenticate(ac);

            DiskShare share = (DiskShare) session.connectShare("samba-share");

            LOG.info("El recurso " + (share.fileExists(resource) ? "SI":"NO") + " existe");
            share.rm(resource);
            return !share.fileExists(resource);
        } catch (Exception e) {
            LOG.info(e.getMessage());
            return false;
        }
    }

}
