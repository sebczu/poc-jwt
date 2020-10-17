package com.sebczu.poc.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

public class RSAJwkGenerator {

  private String privateKey;
  private String publicKey;

  public void generate() {
    generate(2048);
  }

  public void generate(int keySize) {
    try {
      RSAKey rsaKey = new RSAKeyGenerator(keySize)
          .generate();

      privateKey = rsaKey.toJSONString();
      publicKey = rsaKey.toPublicJWK().toJSONString();

      System.out.println("private key:\n" + privateKey);
      System.out.println("public key:\n" + publicKey);

    } catch (JOSEException e) {
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
