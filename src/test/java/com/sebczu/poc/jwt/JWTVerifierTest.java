package com.sebczu.poc.jwt;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class JWTVerifierTest {

  private JWTCreator jwtCreator = new JWTCreator();
  private JWTVerifier jwtVerifier = new JWTVerifier();

  @Test
  public void shouldCreateVerifiedTokenSignedByJWK() {
    RSAJwkGenerator generator = new RSAJwkGenerator();
    generator.generate();
    String privateKey = generator.getPrivateKey();
    String publicKey = generator.getPublicKey();

    String token = jwtCreator.createByJwk(privateKey, "example", Duration.ofHours(1));

    assertTrue(jwtVerifier.verifyByJwk(publicKey, token));
  }

  @Test
  public void shouldCreateVerifiedTokenSignedByPEM() {
    RSAPemGenerator generator = new RSAPemGenerator();
    generator.generate();
    String privateKey = generator.getPrivateKey();
    String publicKey = generator.getPublicKey();

    String token = jwtCreator.createByPem(privateKey, publicKey, "example", Duration.ofHours(1));

    assertTrue(jwtVerifier.verifyByPem(publicKey, token));
  }
}
