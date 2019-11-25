package com.company;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class Main {

    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        int option=0;
        Scanner in = new Scanner(System.in);

        do {
            System.out.println("ESCOGE UNA OPCIÓN:\n" +
                    "1. EJERCICIO 1.1\n" +
                    "2. EJERCICIO 1.2\n" +
                    "3. EJERCICIO 1.3\n" +
                    "4. EJERCICIO 1.4\n" +
                    "5. EJERCICIO 1.5\n" +
                    "6. EJERCICIO 1.6\n" +
                    "7. EJERCICIO 2\n" +
                    "0. SALIR");
            option=in.nextInt();
            switch (option){
                case 1:
                    ejercicio5_1_1();
                    break;
                case 2:
                    ejercicio5_1_2();
                    break;
                case 3:
                    ejercicio5_1_3();
                    break;
                case 4:
                    ejercicio5_1_4();
                    break;
                case 5:
                    ejercicio5_1_5();
                    break;
                case 6:
                    ejercicio5_1_6();
                    break;
                case 7:
                    exercicio5_2();
                    break;
                case 0:
                    System.out.println("gracias por probar el codigo");
                    break;
            }
        }while(option!=0);
    }

    private static void ejercicio5_1_6() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        String ksFile ="/home/dam2a/p5.jks";
        final String ksPsw="p5david";

        ClavesAsimetricas clavesAsimetricas = new ClavesAsimetricas(1024);
        FileInputStream is = new FileInputStream(ksFile);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, ksPsw.toCharArray());
        PublicKey mykey = clavesAsimetricas.getPublicKey(keystore, "p5", "");

        byte[] firma = clavesAsimetricas.getSignature("PRUEBA", (PrivateKey) keystore.getKey("p5", ksPsw.toCharArray()));
        boolean firmavalida = clavesAsimetricas.verifySignature("PRUEBA", firma, mykey);
        if (firmavalida){
            System.out.println("LA FIRMA ES CORRECTA");
        }
        else System.out.println("LA FIRMA NO ES CORRECTA");


    }

    private static void ejercicio5_1_5() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        ClavesAsimetricas clavesAsimetricas = new ClavesAsimetricas(1024);
        String ksFile ="/home/dam2a/p5.jks";
        final String ksPsw="p5david";
        FileInputStream is = new FileInputStream(ksFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, ksPsw.toCharArray());

        byte[] firma = clavesAsimetricas.getSignature("PRUEBA DE FIRMADO", (PrivateKey) keystore.getKey("p5", ksPsw.toCharArray()));
        System.out.println("FIRMA: " + Base64.getEncoder().encodeToString(firma));
    }

    private static void ejercicio5_1_4() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        String ksFile ="/home/dam2a/p5.jks";
        final String ksPsw="p5david";
        ClavesAsimetricas clavesAsimetricas = new ClavesAsimetricas(1024);
        FileInputStream is = new FileInputStream(ksFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, ksPsw.toCharArray());

        PublicKey mykey = clavesAsimetricas.getPublicKey(keystore, "p5", "");
        System.out.println(mykey);
    }

    private static void ejercicio5_1_3() throws CertificateException, FileNotFoundException {
        Scanner in = new Scanner(System.in);
        ClavesAsimetricas clavesAsimetricas = new ClavesAsimetricas(1024);
        System.out.println(clavesAsimetricas.getPublicKey("/home/dam2a/Escriptori/jordi.cer"));
    }

    private static void ejercicio5_1_2() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        String ksFile ="/home/dam2a/p5.jks";
        final String ksPsw="p5david";
        FileInputStream is = new FileInputStream(ksFile);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, ksPsw.toCharArray());

        System.out.println("TIPO DE KEYSTORE: "+keystore.getType());
        System.out.println("NUMERO DE CLAVES: " + keystore.size());
        System.out.print("LISTA DE ALIAS: ");

        Collections.list(keystore.aliases()).forEach(s -> {
            System.out.print(s + " ");
        });
        System.out.println();

        System.out.println("\nCERTIFICADO DE " + keystore.aliases().nextElement() +": " + keystore.getCertificate(keystore.aliases().nextElement()));
        System.out.println("ALGORITMO DE CIFRADO USADO: " + keystore.getKey(keystore.aliases().nextElement(), ksPsw.toCharArray()).getAlgorithm());

        SecretKey secretKey = new ClavesSimetricas().setClau(1024).getsKey();
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(ksPsw.toCharArray());
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        keystore.setEntry("simetrickey",skEntry, protParam);

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keystore.store(fos, ksPsw.toCharArray());
        }
    }

    private static void ejercicio5_1_1(){
        Scanner in = new Scanner(System.in);

        System.out.println("INTRODUCE UN TEXTO PARA CIFRAR: ");
        String textoplano = in.nextLine();

        byte[] textoencriptado = ClavesAsimetricas.getInstance().encryptData(textoplano.getBytes());
        String textodesencriptado = new String(ClavesAsimetricas.getInstance().decryptData(textoencriptado));

        System.out.println("TECTO ENCRIPTADO: " + new String(textoencriptado));
        System.out.println("TEXTO DESENCRIPTADO: " + textodesencriptado);
        System.out.println("CLAVE PUBLICA: " + ClavesAsimetricas.getInstance().getPublic().getFormat());
        System.out.println("CLAVE PRIBADA: " + ClavesAsimetricas.getInstance().getPrivate().getFormat());
        System.out.println("ALGORITMO: " + ClavesAsimetricas.getInstance().getPublic().getAlgorithm());
    }


    private static void exercicio5_2() throws NoSuchAlgorithmException {

        ClavesEmbolcallades clavesEmbolcalladesA = new ClavesEmbolcallades();
        ClavesEmbolcallades clavesEmbolcalladesB = new ClavesEmbolcallades();
        clavesEmbolcalladesA.generateKeys();
        clavesEmbolcalladesB.generateKeys();

        String mensaje = "PRUEBA MENSAJE CIFRADO";
        byte[][] mensajeparaB = clavesEmbolcalladesA.encryptWrappedData(mensaje.getBytes(), clavesEmbolcalladesB.getPublicKey());

        String mensajeDescodificado = new String(clavesEmbolcalladesB.decryptWrappedData(mensajeparaB));
        System.out.println(mensajeDescodificado);
    }

}
