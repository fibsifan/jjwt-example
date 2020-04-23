package de.jball.crypt.playground;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class Main {
	public static void main(String[] args) throws Exception {
		KeyStore pkcs12 = KeyStore.getInstance("pkcs12");
		pkcs12.load(null, "keystorepassword".toCharArray());

		Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
		System.out.println(key.getAlgorithm());
		pkcs12.setKeyEntry("testkey", key, "keypassword".toCharArray(), new Certificate[0]);
		key = pkcs12.getKey("testkey", "keypassword".toCharArray());
		System.out.println(key.getAlgorithm());

		System.out.println(Jwts.builder().signWith(key).setSubject("123").compact());
	}
}
