package com.kuer.test;

import com.kuer.utils.JksUtil;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * JksToP12
 *
 * @author wangkj
 * @date 2022/3/1 17:28
 */
public class JksToP12 {

    /**
     * BKS文件路径
     */
    private static final String BKS_DIRECTORY = "bks/";
    /**
     * BKS文件路径
     */
    private static final String P12_DIRECTORY = "p12/";

    /**
     * jks文件路径
     */
    private static final String JKS_DIRECTORY = "newJks/";

    public static void main(String[] args) {
        try {
            File file = new File(P12_DIRECTORY);
            if (!file.exists()){
                file.mkdirs();
            }
            KeyStore p12KeyStore = JksUtil.generateKeyStore("PKCS12");
            KeyStore jksKeyStore = JksUtil.loadKeyStore("jks", new FileInputStream(JKS_DIRECTORY + "server.jks"), "123456");
            Enumeration<String> aliases = jksKeyStore.aliases();
            while (aliases.hasMoreElements()){
                String alia = aliases.nextElement();
                Certificate certificate = jksKeyStore.getCertificate(alia);
                p12KeyStore.setCertificateEntry(alia, certificate);
            }

            JksUtil.saveKeyStore(P12_DIRECTORY + "server.p12", p12KeyStore, "123456");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
