package com.sebczu.poc.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

public class JWTVerifier {

  public boolean verifyByJwk(String publicJwk, String tokenJWT) {
    try {
      RSAKey rsaPublicKey = RSAKey.parse(publicJwk);
      SignedJWT signedJWT = SignedJWT.parse(tokenJWT);

      JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
      return signedJWT.verify(verifier);
    } catch (ParseException e) {
      e.printStackTrace();
    } catch (JOSEException e) {
      e.printStackTrace();
    }
    return false;
  }

  public boolean verifyByPem(String publicPem, String tokenJWT) {
    String publicJwk = RSAPemConverter.publicPemToJwk(publicPem);
    return verifyByJwk(publicJwk, tokenJWT);
  }

}
