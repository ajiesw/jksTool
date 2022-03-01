package com.kuer.test;

import com.kuer.utils.DateUtil;
import com.kuer.utils.JksUtil;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * JksUtilTest
 *
 * @author wangkj
 * @date 2022/3/1 15:39
 */
public class JksUtilTest {

    /**
     * jks文件路径
     */
    private static final String JKS_DIRECTORY = "newJks/";

    public static void main(String[] args) {
        File file = new File(JKS_DIRECTORY);
        if (!file.exists()){
            file.mkdirs();
        }
        try {
            KeyStore serverKeyStore = JksUtil.generateKeyStore();
            KeyPair sererKeyPair = JksUtil.generateRsaKeyPair();
            X509Certificate serverCertificate = JksUtil.createRsaCertificate(sererKeyPair,
                    DateUtil.calculateDate(0),
                    DateUtil.calculateDate(365 * 24),
                    "wkj");
            JksUtil.storeKeyEntry("server", serverKeyStore, sererKeyPair, "123456", serverCertificate);

            KeyStore clientKeyStore = JksUtil.generateKeyStore();
            KeyPair clientKeyPair = JksUtil.generateRsaKeyPair();
            X509Certificate clientCertificate = JksUtil.createRsaCertificate(sererKeyPair,
                    DateUtil.calculateDate(0),
                    DateUtil.calculateDate(365 * 24),
                    "wkj");
            JksUtil.storeKeyEntry("client", clientKeyStore, clientKeyPair, "123456", clientCertificate);

            clientKeyStore.setCertificateEntry("server", serverCertificate);
            serverKeyStore.setCertificateEntry("client", clientCertificate);

            JksUtil.saveKeyStore(JKS_DIRECTORY + "server.jks", serverKeyStore, "123456");
            JksUtil.saveKeyStore(JKS_DIRECTORY + "client.jks", clientKeyStore, "123456");


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
