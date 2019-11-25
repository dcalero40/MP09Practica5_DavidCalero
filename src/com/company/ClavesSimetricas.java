package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class ClavesSimetricas {
    
    private static ClavesSimetricas clavesSimetricas;
    private SecretKey sKey;

    private SecretKey keygenKeyGeneration(int keySize) {
        sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    public byte[] encryptData(byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public byte[] decryptData(byte[] data) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error desxifrant les dades: " + ex);
        }

        return decryptedData;
    }

    private SecretKey passwordKeyGeneration(String passphrase, int keySize) {
        sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = passphrase.getBytes("UTF8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }



    protected ClavesSimetricas(){sKey = keygenKeyGeneration(256);}
    private ClavesSimetricas(String passphrase){sKey = passwordKeyGeneration(passphrase,256);}

    public static ClavesSimetricas getInstance(){
        if (clavesSimetricas == null) clavesSimetricas = new ClavesSimetricas();
        return clavesSimetricas;
    }

    public void setClau(String passphrase, int keySize){
        ClavesSimetricas.getInstance().sKey = ClavesSimetricas.getInstance().passwordKeyGeneration(passphrase, keySize);
    }

    public ClavesSimetricas setClau(int keySize){
        ClavesSimetricas.getInstance().sKey = ClavesSimetricas.getInstance().keygenKeyGeneration(keySize);
        return this;
    }

    public SecretKey getsKey() {
        return sKey;
    }
}
