package com.sebczu.poc.jwt;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JWTCreatorTest {

  private JWTCreator jwtCreator = new JWTCreator();

  @Test
  public void shouldCreateVerifiedTokenSignedByJWK() throws ParseException {
    RSAJwkGenerator generator = new RSAJwkGenerator();
    generator.generate();
    String privateKey = generator.getPrivateKey();

    String token = jwtCreator.createByJwk(privateKey, "example", Duration.ofHours(1));
    JOSEObject plainJWT = JOSEObject.parse(token);

    assertEquals(plainJWT.getHeader().getAlgorithm(), JWSAlgorithm.RS256);
    assertEquals(plainJWT.getPayload().toJSONObject().get("sub"), "example");
  }

  @Test
  public void shouldCreateVerifiedTokenSignedByPEM() throws ParseException {
    RSAPemGenerator generator = new RSAPemGenerator();
    generator.generate();
    String privateKey = generator.getPrivateKey();
    String publicKey = generator.getPublicKey();

    String token = jwtCreator.createByPem(privateKey, publicKey, "example", Duration.ofHours(1));
    JOSEObject plainJWT = JOSEObject.parse(token);

    assertEquals(plainJWT.getHeader().getAlgorithm(), JWSAlgorithm.RS256);
    assertEquals(plainJWT.getPayload().toJSONObject().get("sub"), "example");
  }
}
