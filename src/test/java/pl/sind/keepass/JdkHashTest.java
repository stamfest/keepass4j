package pl.sind.keepass;

import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import pl.sind.keepass.crypto.CipherException;
import pl.sind.keepass.hash.JdkSHA256Hash;

@RunWith(JUnit4.class)
public class JdkHashTest extends HashTestBase{

	@Before
	public void prepare() throws CipherException {
		hash = new JdkSHA256Hash();
	}


}
