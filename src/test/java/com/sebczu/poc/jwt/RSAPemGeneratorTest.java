package com.sebczu.poc.jwt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RSAPemGeneratorTest {

  RSAJwkGenerator generator = new RSAJwkGenerator();

  @Test
  public void shouldGeneratePublicKey() {
    generator.generate();
    String publicKey = generator.getPublicKey();

    String pemPublicKey = RSAJwkConverter.jwkToPem(publicKey);
    String jwkPublicKey = RSAPemConverter.publicPemToJwk(pemPublicKey);

    assertEquals(publicKey, jwkPublicKey);
  }

  @Test
  public void shouldGeneratePrivateKey() {
    generator.generate();
    String privateKey = generator.getPrivateKey();
    String publicKey = generator.getPublicKey();

    String pemPrivateKey = RSAJwkConverter.jwkToPem(privateKey);
    String pemPublicKey = RSAJwkConverter.jwkToPem(publicKey);
    String jwkPrivateKey = RSAPemConverter.privatePemToJwk(pemPrivateKey, pemPublicKey);

    assertEquals(privateKey, jwkPrivateKey);
  }
}
