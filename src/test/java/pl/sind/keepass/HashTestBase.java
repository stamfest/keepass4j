package pl.sind.keepass;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Before;
import org.junit.Test;

import pl.sind.keepass.crypto.CipherException;
import pl.sind.keepass.hash.BcSHA256Hash;
import pl.sind.keepass.hash.Hash;

public abstract class HashTestBase {

	private String stringOne = "hash target string";
	private String stringTwo = " another part of string";
	private String both = stringOne + stringTwo;
	private byte[] hashOne = new byte[] { 68, 19, -22, 54, 91, 82, -107, -84,
			-54, 104, 49, -101, 126, -47, -79, -84, -81, -27, -88, -41, -31,
			53, -121, -102, 81, -89, -26, -20, -5, 106, -125, 114 };
	private byte[] hashTwo = new byte[] { 96, 63, 43, -30, -120, 125, -54, 25,
			-88, 55, 127, 111, 114, 2, 42, 39, 104, 6, -1, 103, 14, 115, 38,
			-106, -89, -49, 31, 25, 5, 43, -119, -73 };
	private byte[] hashBoth = new byte[] { -53, -101, -48, 104, 29, 87, -119,
			106, -114, 88, 110, -52, -15, -18, -43, 101, 84, -110, -60, -64,
			101, 96, 73, -121, -98, 25, 81, -39, -104, 123, -71, -97 };

	protected Hash hash;

	@Test
	public void hashOne() throws CipherException {
		byte[] result = hash.hash(stringOne.getBytes());
		assertArrayEquals(hashOne, result);

	}

	@Test
	public void hashTwo() throws CipherException {
		byte[] result = hash.hash(stringTwo.getBytes());
		assertArrayEquals(hashTwo, result);

	}

	@Test
	public void hashBothSingle() throws CipherException {
		byte[] result = hash.hash(both.getBytes());
		assertArrayEquals(hashBoth, result);

	}
	
	@Test
	public void hashBothPartial() throws CipherException {
		hash.update(stringOne.getBytes());
		hash.update(stringTwo.getBytes());
		byte[] result = hash.digest();
		assertArrayEquals(hashBoth, result);

	}

}
