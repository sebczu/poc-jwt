package com.sebczu.poc.jwt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RSAJwkGeneratorTest {

  RSAPemGenerator generator = new RSAPemGenerator();

  @Test
  public void shouldGeneratePublicKey() {
    generator.generate();
    String publicKey = generator.getPublicKey();

    String jwkPublicKey = RSAPemConverter.publicPemToJwk(publicKey);
    String pemPublicKey = RSAJwkConverter.jwkToPem(jwkPublicKey);

    assertEquals(publicKey, pemPublicKey);
  }

  @Test
  public void shouldGeneratePrivateKey() {
    generator.generate();
    String privateKey = generator.getPrivateKey();
    String publicKey = generator.getPublicKey();

    String jwkPrivateKey = RSAPemConverter.privatePemToJwk(privateKey, publicKey);
    String pemPrivateKey = RSAJwkConverter.jwkToPem(jwkPrivateKey);

    assertEquals(privateKey, pemPrivateKey);
  }
}
