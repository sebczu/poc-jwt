package com.sebczu.poc.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;

public class RSAConverter {

  private final static Base64.Encoder encoder = Base64.getMimeEncoder();
  private final static Base64.Decoder decoder = Base64.getMimeDecoder();

  public String jwkToPem(String jwk) {
    try {
      RSAKey key = RSAKey.parse(jwk);

      if (key.isPrivate()) {
        byte[] privateKeyEncoded = key.toRSAPrivateKey().getEncoded();
        String privateKey = encoder.encodeToString(privateKeyEncoded);
        System.out.println("private key:\n-----BEGIN PRIVATE KEY-----\n" + privateKey + "\n-----END PRIVATE KEY-----");
        return privateKey;
      } else {
        byte[] publicKeyEncoded = key.toRSAPublicKey().getEncoded();
        String publicKey = encoder.encodeToString(publicKeyEncoded);
        System.out.println("public key:\n-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----");
        return publicKey;
      }

    } catch (ParseException e) {
      e.printStackTrace();
    } catch (JOSEException e) {
      e.printStackTrace();
    }
    return null;
  }

  public String publicPemToJwk(String pem) {
    try {
      RSAPublicKey rsaPublicKey = publicPemToRSAPublicKey(pem);

      RSAKey jwk = new RSAKey.Builder(rsaPublicKey).build();
      String publicKey = jwk.toPublicJWK().toJSONString();

      System.out.println("public key:\n" + publicKey);
      return  publicKey;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }
    return null;
  }

  public String privatePemToJwk(String privatePem, String publicPem) {
    try {
      byte[] decoded = decoder.decode(privatePem);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
      RSAPublicKey rsaPublicKey = publicPemToRSAPublicKey(publicPem);

      RSAKey jwk = new RSAKey.Builder(rsaPublicKey)
          .privateKey(rsaPrivateKey)
          .build();
      String privateKey = jwk.toJSONString();

      System.out.println("private key:\n" + privateKey);
      return  privateKey;
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }
    return null;
  }

  private RSAPublicKey publicPemToRSAPublicKey(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] decoded = decoder.decode(pem);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
  }

}
