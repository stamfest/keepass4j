package pl.sind.keepass;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import junit.framework.TestCase;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import pl.sind.keepass.exceptions.KeePassDataBaseException;
import pl.sind.keepass.kdb.KeePassDataBase;
import pl.sind.keepass.kdb.KeePassDataBaseManager;
import pl.sind.keepass.kdb.v1.KeePassDataBaseV1;

@RunWith(JUnit4.class)
public class FactoryTest {

	@Test
	public void openPasswordKdb() throws Exception {
		KeePassDataBase db = KeePassDataBaseManager.openDataBase(new File(
				"testing-pass.kdb"), null, "testing");
		assertNotNull(db);
	}
	
	@Test
	public void openKeyFileKdb() throws Exception {
		KeePassDataBase keePassDb = KeePassDataBaseManager.openDataBase(new File(
				"testing-key.kdb"), new File("testing-key.key"), null);
		KeePassDataBaseV1 kdb1 = (KeePassDataBaseV1) keePassDb; 
		System.out.println(kdb1.getGroups());
		System.out.println(kdb1.getEntries());
		assertNotNull(keePassDb);
	}
	
	@Test
	public void openKeyFilePasswordKdb() throws Exception {
		KeePassDataBase keePassDb = KeePassDataBaseManager.openDataBase(new File(
				"testing-pass-key.kdb"), new File("testing-key.key"), "testing");
		KeePassDataBaseV1 kdb1 = (KeePassDataBaseV1) keePassDb; 
		System.out.println(kdb1.getGroups());
		System.out.println(kdb1.getEntries());
		assertNotNull(keePassDb);
	}

	
	@Test
	public void openNullsKdb() throws Exception {
		try{
		KeePassDataBaseManager.openDataBase(new File(
				"testing-pass.kdb"), null, null);
		}catch(KeePassDataBaseException e){
			//good exceptiob
			return;
		}
		TestCase.fail("Exception should be thrown");
	}
	@Test
	public void openPasswordXkdb() throws Exception {
		try {
			KeePassDataBaseManager.openDataBase(new File("testing-pass.kdbx"),
					null, "testing");
		} catch (RuntimeException e) {
			// good exception
			return;
		}
		TestCase.fail("Exception should be thrown");
	}
}
