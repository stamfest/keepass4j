package pl.sind.keepass;

import static org.junit.Assert.assertArrayEquals;

import java.util.Random;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import pl.sind.keepass.crypto.BcAESCipher;
import pl.sind.keepass.hash.BcSHA256Hash;

@RunWith(JUnit4.class)
public class CipherTest {

	String target = "Tekst Szyfrowany";
	String password = "password";
	byte[] key;
	byte[] targetBytes = target.getBytes();

	byte[] reference = new byte[] { -112, -49, -22, -75, -128, -75, 127, 88,
			-74, -122, 67, -41, 59, 24, 22, -101, -79, 88, -35, 111, 123, -115,
			40, 68, -75, -69, -34, -9, 98, 101, -126, (byte) 0xe3 };

	byte[] iv = new byte[] { 00, 01, 02, 03, 04, 05, 06, 07, 00, 01, 02, 03,
			04, 05, 06, 07 };

	@Before
	public void prepare() throws Exception {
		BcSHA256Hash hash = new BcSHA256Hash();
		key = hash.hash(password.getBytes());
	}

	@Test
	public void encryptBc() throws Exception {
		BcAESCipher cipher = new BcAESCipher();
		byte[] result = cipher.encrypt(key, targetBytes, iv, 1,true);
		assertArrayEquals(reference, result);
	}
	
	
	
	@Test
	public void decryptBc() throws Exception {
		BcAESCipher cipher = new BcAESCipher();
		byte[] result = cipher.decrypt(key, reference, iv);
		assertArrayEquals(targetBytes, result);
	}

	@Test
	public void encryptionRoundtrip() throws Exception {
		BcAESCipher cipher = new BcAESCipher();

		Random r = new Random();
		byte[] source = new byte[r.nextInt(512)+128];
		byte[] key = new byte[32];
		byte[] iv = new byte[16];
		
		r.nextBytes(key);
		r.nextBytes(source);
		r.nextBytes(iv);
		
		byte[] encrypted = cipher.encrypt(key, source, iv, 1,true);
		byte[] decrypted = cipher.decrypt(key, encrypted, iv);
		
		assertArrayEquals(source, decrypted);
		
	}
}
