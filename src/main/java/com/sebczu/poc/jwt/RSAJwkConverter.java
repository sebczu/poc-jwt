package com.sebczu.poc.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.text.ParseException;
import java.util.Base64;

public class RSAJwkConverter {

  private final static Base64.Encoder encoder = Base64.getMimeEncoder();

  public static String jwkToPem(String jwk) {
    try {
      RSAKey key = RSAKey.parse(jwk);

      if (key.isPrivate()) {
        byte[] privateKeyEncoded = key.toRSAPrivateKey().getEncoded();
        String privateKey = addPrefixAndPostfixForPrivateKey(encoder.encodeToString(privateKeyEncoded));
        System.out.println("private key[pem]:");
        System.out.println(privateKey);
        return privateKey;
      } else {
        byte[] publicKeyEncoded = key.toRSAPublicKey().getEncoded();
        String publicKey = addPrefixAndPostfixForPublicKey(encoder.encodeToString(publicKeyEncoded));
        System.out.println("public key[pem]:");
        System.out.println(publicKey);
        return publicKey;
      }

    } catch (ParseException e) {
      e.printStackTrace();
    } catch (JOSEException e) {
      e.printStackTrace();
    }
    return null;
  }

  public static String addPrefixAndPostfixForPrivateKey(String privateKey) {
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN PRIVATE KEY-----");
    builder.append(System.lineSeparator());
    builder.append(privateKey);
    builder.append(System.lineSeparator());
    builder.append("-----END PRIVATE KEY-----");
    return builder.toString();
  }

  public static String addPrefixAndPostfixForPublicKey(String publicKey) {
    StringBuilder builder = new StringBuilder();
    builder.append("-----BEGIN PUBLIC KEY-----");
    builder.append(System.lineSeparator());
    builder.append(publicKey);
    builder.append(System.lineSeparator());
    builder.append("-----END PUBLIC KEY-----");
    return builder.toString();
  }
}