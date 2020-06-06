package de.jball.crypt.playground;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class Main {
	private static final char[] KEY_PASSWORD = "keypassword".toCharArray();
	private static final char[] KEY_STORE_PASSWORD = "keystorepassword".toCharArray();

	private static final List<String> KEY_STORE_TYPES = Arrays.asList("pkcs12", "jks", "jceks", "bks", "uber", "bcpkcs12");
	private static final List<KeyStore> KEY_STORES;

	static {
		try {
			System.out.println(String.valueOf(javax.crypto.Cipher.getMaxAllowedKeyLength("AES")));
			Security.addProvider(new BouncyCastleProvider());
			System.out.println(KeyStore.getDefaultType());
			System.out.println();

			List<KeyStore> tmp = new ArrayList<>();
			for (String storeType : KEY_STORE_TYPES) {
				KeyStore ks = KeyStore.getInstance(storeType);
				ks.load(null, KEY_STORE_PASSWORD);
				tmp.add(ks);
			}
			KEY_STORES = Collections.unmodifiableList(tmp);
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	public static void main(String[] args) throws Exception {
		for (SignatureAlgorithm sa : SignatureAlgorithm.values()) {
			if (sa != SignatureAlgorithm.NONE) {
				printKeyNamesForEachKeystore(sa);
			}
		}
	}

	private static void printKeyNamesForEachKeystore(SignatureAlgorithm sa) throws Exception {
		final Key k;
		final KeyPair pair;
		if (sa.isHmac()) {
			k = Keys.secretKeyFor(sa);
			pair = null;
		} else {
			pair = Keys.keyPairFor(sa);
			k = pair.getPrivate();
		}

		System.out.println(sa.getValue());
		System.out.println("jca name   : " + k.getAlgorithm());
		Certificate[] chain = genSelfSignedCertificate(pair, sa);

		for (KeyStore store : KEY_STORES) {
			if (("jks".equals(store.getType()) || "bcpkcs12".equals(store.getType())) && sa.isHmac()) {
				System.out.println(store.getType() + " name: ");
			} else {
				store.setKeyEntry(sa.getJcaName(), k, KEY_PASSWORD, chain);
				System.out.println(store.getType() + " name: " + store.getKey(sa.getJcaName(), KEY_PASSWORD).getAlgorithm());
			}
		}
		System.out.println(System.lineSeparator());
	}

	private static Certificate[] genSelfSignedCertificate(final KeyPair keyPair, SignatureAlgorithm sa) throws Exception {
		if (keyPair == null) {
			return new Certificate[0];
		}
		X500Name dnName = new X500Name("CN=pkcs12test");
		BigInteger serial = BigInteger.ONE;
		ContentSigner signer;
		if ("RSASSA-PSS".equalsIgnoreCase(sa.getJcaName())) {
			signer = new JcaContentSignerBuilder("SHA256WITHRSAANDMGF1").build(keyPair.getPrivate());
		} else {
			signer = new JcaContentSignerBuilder(sa.getJcaName()).build(keyPair.getPrivate());
		}
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, serial, Date.from(Instant.now()), Date.from(ZonedDateTime.now().plus(1, ChronoUnit.YEARS).toInstant()), dnName, keyPair.getPublic());
		return new Certificate[] {new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certBuilder.build(signer))};
	}
}
