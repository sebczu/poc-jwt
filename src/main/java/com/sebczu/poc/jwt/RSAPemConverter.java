package com.sebczu.poc.jwt;

import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAPemConverter {

  private final static Base64.Decoder decoder = Base64.getMimeDecoder();

  public static String publicPemToJwk(String pem) {
    try {
      RSAPublicKey rsaPublicKey = publicKeyPemToRSA(pem);

      RSAKey jwk = new RSAKey.Builder(rsaPublicKey).build();
      String publicKey = jwk.toPublicJWK().toJSONString();

      System.out.println("converted public key[jwk]:");
      System.out.println(publicKey);
      return  publicKey;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }
    return null;
  }

  public static String privatePemToJwk(String privatePem, String publicPem) {
    try {
      RSAPrivateKey rsaPrivateKey = privateKeyPemToRSA(privatePem);
      RSAPublicKey rsaPublicKey = publicKeyPemToRSA(publicPem);

      RSAKey jwk = new RSAKey.Builder(rsaPublicKey)
          .privateKey(rsaPrivateKey)
          .build();
      String privateKey = jwk.toJSONString();

      System.out.println("converted private key[jwk]:");
      System.out.println(privateKey);
      return  privateKey;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }
    return null;
  }

  private static RSAPublicKey publicKeyPemToRSA(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] decoded = decoder.decode(getBodyPublicKey(pem));
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
  }

  private static RSAPrivateKey privateKeyPemToRSA(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] decoded = decoder.decode(getBodyPrivateKey(pem));
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
  }

  private static String getBodyPublicKey(String publicKey) {
    String publicKeyBody = publicKey.replace("-----BEGIN PUBLIC KEY-----" + System.lineSeparator(), "");
    return publicKeyBody.replace(System.lineSeparator() + "-----END PUBLIC KEY-----", "");
  }

  private static String getBodyPrivateKey(String privateKey) {
    String privateKeyBody = privateKey.replace("-----BEGIN PRIVATE KEY-----" + System.lineSeparator(), "");
    return privateKeyBody.replace(System.lineSeparator() + "-----END PRIVATE KEY-----", "");
  }
}
