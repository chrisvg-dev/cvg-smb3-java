package com.casystem.ka.test.samba;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.FileAttributes;
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
import java.util.logging.Logger;

public class SmbRemoteAccess extends AbstractRemoteAccess {

    private static final String CLASS_VERSION = "V3";

    private static final Logger LOG = Logger.getLogger(SmbRemoteAccess.class.getName());
    public SmbRemoteAccess() {}

    @Override
    public String read(String resource) {
        try {
            String result = "";
            SambaConfig sambaConfig = this.getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig.getShare());

            if ( !share.fileExists(sambaConfig.getFilePath()) ) return null;

            File file = share.openFile(sambaConfig.getFilePath(),
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
            share.close();

            return result;
        } catch (Exception e){
            LOG.info(e.getMessage());
            return null;
        }
    }
    @Override
    public byte[] readBinary(String resource) {
        try{
            SambaConfig sambaConfig = this.getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig.getShare());

            if ( !share.fileExists(sambaConfig.getFilePath()) ) {
                LOG.info("Archivo no encontrado");
                return null;
            }

            File file = share.openFile(sambaConfig.getFilePath(),
                    EnumSet.of(AccessMask.FILE_READ_DATA),
                    null,
                    SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN,
                    null);

            byte[] buffer = new byte[2 * BUFFER_SIZE];
            int bytesRead = 0;
            BufferedInputStream bi = new BufferedInputStream(file.getInputStream());
            ByteArrayOutputStream bao = new ByteArrayOutputStream (2 * BUFFER_SIZE);

            while ((bytesRead = bi.read(buffer)) != -1) {
                bao.write(buffer, 0, bytesRead);
            }

            bao.close();
            bi.close();

            return bao.toByteArray();
        } catch (Exception e) {
            LOG.info(e.getMessage());
            return null;
        }
    }

    @Override
    public boolean write(String resource, String lines, String encoding) {
        try  {
            SambaConfig sambaConfig = this.getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig.getShare());

            int lastSlash = sambaConfig.getFilePath().lastIndexOf("/");
            String directory = sambaConfig.getFilePath().substring(0, lastSlash);

            if (!share.folderExists(directory)) share.mkdir(directory);

            File file = share.openFile(sambaConfig.getFilePath(),
                    EnumSet.of(AccessMask.FILE_WRITE_DATA),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_CREATE,
                    EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

            byte[] lineBytes = lines.getBytes();
            OutputStream os = file.getOutputStream();
            os.write(lineBytes);
            os.flush();
            os.close();
            //share.close();
            file.close();

            return share.fileExists(sambaConfig.getFilePath());
        } catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }
    }
    @Override
    public boolean write(String resource, byte[] lines) {
        try  {
            SambaConfig sambaConfig = this.getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig.getShare());

            int lastSlash = sambaConfig.getFilePath().lastIndexOf("/");
            String directory = sambaConfig.getFilePath().substring(0, lastSlash);

            if (!share.folderExists(directory)) share.mkdir(directory);

            File file = share.openFile(sambaConfig.getFilePath(),
                    EnumSet.of(AccessMask.FILE_WRITE_DATA),
                    EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
                    SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_CREATE,
                    EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

            OutputStream os = file.getOutputStream();
            os.write(lines);
            os.flush();
            os.close();
            //share.close();
            file.close();

            return share.fileExists(sambaConfig.getFilePath());
        } catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }
    }
    @Override
    public String[] list(String resource, String filter) {
        try {
            SambaConfig sambaConfig = this.getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig);
            System.out.println(sambaConfig);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig.getShare());
            String filterFormat = "*."+filter;

            return share.list(sambaConfig.getPath(), filterFormat).stream()
                    .map(item ->  item.getFileName())
                    .toArray(String[]::new);

        } catch (Exception e) {
            LOG.info(e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }
    @Override
    public boolean move(String resource, String sourcePath, String destinationPath)  {
        try {
            SambaConfig sambaConfig = this.getParametersFromURL(sourcePath);
            Session session = getAuthentication(sambaConfig);

            DiskShare share = (DiskShare) session.connectShare(sambaConfig.getShare());

            if ( !share.fileExists(sambaConfig.getFilePath()) ) return false;

            File oldFile = share.openFile(
                    sambaConfig.getFilePath(),
                    EnumSet.of(AccessMask.FILE_READ_DATA),null,
                    SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN,
                    EnumSet.of(SMB2CreateOptions.FILE_DIRECTORY_FILE));

            if (!share.folderExists(destinationPath)) share.mkdir(destinationPath);

            String destinationFile = destinationPath + "/" + resource;
            File newFile = share.openFile(destinationFile,
                    EnumSet.of(AccessMask.FILE_WRITE_DATA),
                    null,
                    SMB2ShareAccess.ALL,
                    null,
                    null);
            copyFile(oldFile, newFile);

            boolean fileExists = share.fileExists(destinationFile);

            if (fileExists) {
                share.rm( sambaConfig.getFilePath() );
                oldFile.close();
                newFile.close();
                share.close();
            }
            return fileExists;
        } catch (Exception e) {
            throw new RuntimeException("El archivo no existe");
        }
    }
    @Override
    public boolean delete(String resource) {
        try {
            SambaConfig sambaConfig = this.getParametersFromURL(resource);
            Session session = getAuthentication(sambaConfig);

            DiskShare share = (DiskShare) session.connectShare("samba-share");

            if (!share.fileExists(sambaConfig.getFilePath())) throw new RuntimeException("No existe el archivo...");

            share.rm( sambaConfig.getFilePath() );
            return !share.fileExists( sambaConfig.getFilePath() );
        } catch (Exception e) {
            LOG.info(e.getMessage());
            return false;
        }
    }

    /**
     * This method generates a session in order to connect this app to samba on a remote server
     * Requires an object with connection params
     * @param params
     * @return
     * @throws Exception
     */
    private static Session getAuthentication(SambaConfig params) throws Exception {
        SMBClient client = new SMBClient();
        Connection connection = client.connect(params.getHost());
        AuthenticationContext ac = new AuthenticationContext(params.getUser(), params.getPassword().toCharArray(), params.getDomain());;
        return connection.authenticate(ac);
    }

    /**
     * This method copies all content from a source file to a destination file, and after process it deletes the original file
     * @param source
     * @param destination
     * @throws IOException
     */
    public static void copyFile(File source, File destination) throws IOException {
        byte[] buffer = new byte[8 * BUFFER_SIZE];
        try(InputStream in = source.getInputStream()) {
            try(OutputStream out = destination.getOutputStream()) {
                int bytesRead;
                while((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    /**
     * This method takes all the URL parameters and puts them into a POJO class to connect to a remote server using OOP
     * @param url
     * @return
     */
    public SambaConfig getParametersFromURL(String url){
        SambaConfig samba = new SambaConfig();
        String newURL = url.replaceAll("smb://", "");

        if(newURL.contains(":")){
            String[] splitData = newURL.split("[;|:|@|$]");
            if(splitData.length > 0 && splitData.length == 5){
                samba.setDomain( splitData[0] );
                samba.setUser( splitData[1] );
                samba.setPassword( splitData[2] );
                samba.setHost( splitData[3] );
                samba.setPath( splitData[4] );
            } else {
                throw new RuntimeException("ERROR: La URL no está bien formada.");
            }
        }

        if(samba.getHost().contains("/")){
            String[] splitHost = samba.getHost().split("/");
            samba.setHost(splitHost[0]);
            samba.setShare(splitHost[1]);
        }

        if(samba.getPath().contains(".")){
            samba.setFilePath( samba.getPath() );

            int lastSlashIndex = samba.getPath().lastIndexOf("/");
            String newPath = samba.getPath().substring(0, lastSlashIndex);
            samba.setPath( newPath );
        }

        if(url.contains("$")){
            samba.setShare( samba.getShare() );
//            sambaBO.setShare( sambaBO.getShare() + "$" );
        }
        return samba;
    }
}
