package com.casystem.ka.test.samba;

import java.util.Arrays;
import java.util.logging.Logger;

public class Main {
    private static final Logger LOG = Logger.getLogger(SmbRemoteAccess.class.getName());

    public static void main(String[] args) {
        String URL = "smb://192.168.163.128;cristian:12345@192.168.163.128/samba-share$/temp/file.txt";

        //String text = new SmbRemoteAccess().read(URL); //WORKS
        //System.out.println(text); // WORKS

//        boolean deleted = new SmbRemoteAccess().delete(URL); //WORKS
//        System.out.println(deleted); // WORKS

//        boolean created = new SmbRemoteAccess().write(URL, "Hello \n World jeje", "UTF8");
//        System.out.println(created);


//        boolean moved = new SmbRemoteAccess().move("file.txt", URL, "/temp");
//        System.out.println(moved);
        Arrays.stream(new SmbRemoteAccess().list(URL, "*")).forEach(System.out::println);  //WORKS
    }
}
