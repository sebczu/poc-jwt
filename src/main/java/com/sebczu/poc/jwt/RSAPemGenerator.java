package com.sebczu.poc.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class RSAPemGenerator {

  private final static String ALGORITHM = "RSA";
  private final static Base64.Encoder encoder = Base64.getMimeEncoder();
  private String privateKey;
  private String publicKey;

  public void generate() {
    generate(2048);
  }

  public void generate(int keySize) {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
      keyPairGenerator.initialize(keySize);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      byte[] privateKeyEncoded = keyPair.getPrivate().getEncoded();
      byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();

      privateKey = RSAJwkConverter.addPrefixAndPostfixForPrivateKey(encoder.encodeToString(privateKeyEncoded));
      publicKey = RSAJwkConverter.addPrefixAndPostfixForPublicKey(encoder.encodeToString(publicKeyEncoded));

      System.out.println("private key[pem]:");
      System.out.println(privateKey);
      System.out.println("public key[pem]:");
      System.out.println(publicKey);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }
}
