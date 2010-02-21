package pl.sind.keepass;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import pl.sind.keepass.crypto.CipherException;
import pl.sind.keepass.hash.BcSHA256Hash;

@RunWith(JUnit4.class)
public class BcHashTest extends HashTestBase{


	@Before
	public void prepare() throws CipherException {
		hash = new BcSHA256Hash();
	}


}
