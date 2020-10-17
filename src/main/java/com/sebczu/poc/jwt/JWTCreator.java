package com.sebczu.poc.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.sql.Timestamp;
import java.text.ParseException;
import java.time.LocalDateTime;

public class JWTCreator {

  private final static JWSAlgorithm algorithm = JWSAlgorithm.RS256;

  public String createByJwk(String privateJwk, String subject, LocalDateTime expirationDate) {
    try {
      RSAKey rsaPrivate = RSAKey.parse(privateJwk);
      JWSSigner signer = new RSASSASigner(rsaPrivate);

      SignedJWT jwt = new SignedJWT(getHeader(rsaPrivate), getClaims(subject, expirationDate));
      jwt.sign(signer);
      String tokenJWT = jwt.serialize();
      System.out.println("token:");
      System.out.println(tokenJWT);
      return tokenJWT;

    } catch (ParseException e) {
      e.printStackTrace();
    } catch (JOSEException e) {
      e.printStackTrace();
    }
    return null;
  }

  public String createByPem(String privatePem, String publicPem, String subject, LocalDateTime expirationDate) {
    String privateJwk = RSAPemConverter.privatePemToJwk(privatePem, publicPem);
    return createByJwk(privateJwk, subject, expirationDate);
  }

  private JWSHeader getHeader(RSAKey rsaPrivate) {
    return new JWSHeader.Builder(algorithm)
        .keyID(rsaPrivate.getKeyID())
        .build();
  }

  private JWTClaimsSet getClaims(String subject, LocalDateTime expirationDate) {
    return new JWTClaimsSet.Builder()
        .subject(subject)
        .expirationTime(Timestamp.valueOf(expirationDate))
        .build();
  }

}
