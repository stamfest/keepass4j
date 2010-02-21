package pl.sind.keepass;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import pl.sind.keepass.kdb.v1.Database;

@RunWith(JUnit4.class)
public class KeePassApiTest {

	@Test
	public void openPassword() throws NoSuchAlgorithmException,
			InvalidCipherTextException, IOException {
		File dbFile = new File("testing-pass.kdb");
		Database db = new Database(dbFile, null, "testing");
		FileInputStream fin = new FileInputStream(dbFile);
		byte[] file = new byte[(int) dbFile.length()];
		fin.read(file);
		db.decrypt(file);

	}

	@Test
	public void openKeyFile() throws NoSuchAlgorithmException, InvalidCipherTextException, IOException {
		File dbFile = new File("testing-key.kdb");
		File keyFile = new File("testing-key.key");
		Database db = new Database(dbFile, keyFile, null);
		FileInputStream fin = new FileInputStream(dbFile);
		byte[] file = new byte[(int) dbFile.length()];
		fin.read(file);

	}

	@Test
	public void openPasswordKeyFile() throws NoSuchAlgorithmException, InvalidCipherTextException, IOException {
		File dbFile = new File("testing-pass-key.kdb");
		File keyFile = new File("testing-key.key");
		Database db = new Database(dbFile, keyFile, "testing");
		FileInputStream fin = new FileInputStream(dbFile);
		byte[] file = new byte[(int) dbFile.length()];
		fin.read(file);

	}

}
