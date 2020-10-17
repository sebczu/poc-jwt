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
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Date;

public class JWTCreator {

  private final static JWSAlgorithm algorithm = JWSAlgorithm.RS256;

  public String createByJwk(String privateJwk, String subject, Duration duration) {
    try {
      RSAKey rsaPrivate = RSAKey.parse(privateJwk);
      JWSSigner signer = new RSASSASigner(rsaPrivate);

      SignedJWT jwt = new SignedJWT(getHeader(), getClaims(subject, duration));
      jwt.sign(signer);
      String tokenJwt = jwt.serialize();
      System.out.println("token:");
      System.out.println(tokenJwt);
      return tokenJwt;

    } catch (ParseException e) {
      e.printStackTrace();
    } catch (JOSEException e) {
      e.printStackTrace();
    }
    return null;
  }

  public String createByPem(String privatePem, String publicPem, String subject, Duration duration) {
    String privateJwk = RSAPemConverter.privatePemToJwk(privatePem, publicPem);
    return createByJwk(privateJwk, subject, duration);
  }

  private JWSHeader getHeader() {
    return new JWSHeader.Builder(algorithm)
        .build();
  }

  private JWTClaimsSet getClaims(String subject, Duration duration) {
    return new JWTClaimsSet.Builder()
        .subject(subject)
        .expirationTime(getExpirationDate(duration))
        .build();
  }

  private Date getExpirationDate(Duration duration) {
    LocalDateTime expirationDate = LocalDateTime.now().plus(duration);
    return Timestamp.valueOf(expirationDate);
  }

}
