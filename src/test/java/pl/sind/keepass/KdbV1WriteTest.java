/*
 * (c) 2014 by Peter Stamfest
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package pl.sind.keepass;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;
import pl.sind.keepass.exceptions.KeePassDataBaseException;
import pl.sind.keepass.exceptions.UnsupportedDataBaseException;
import pl.sind.keepass.kdb.KeePassDataBase;
import pl.sind.keepass.kdb.KeePassDataBaseManager;
import pl.sind.keepass.kdb.v1.Entry;
import pl.sind.keepass.kdb.v1.Group;
import pl.sind.keepass.kdb.v1.KeePassDataBaseV1;

/**
 *
 * @author peter
 */
public class KdbV1WriteTest {
    	@Test
	public void writePasswordKdb() throws Exception {
		KeePassDataBase db = KeePassDataBaseManager.openDataBase(new File(
				"testing-pass.kdb"), null, "testing");
		assertNotNull(db);
		KeePassDataBaseV1 kdb1 = (KeePassDataBaseV1) db;
	
		FileOutputStream fos = new FileOutputStream("testing-pass-out.kdb");
		kdb1.write_copy_to_stream(fos);
	        fos.close();
		
		KeePassDataBase db2 = KeePassDataBaseManager.openDataBase(new File(
				"testing-pass-out.kdb"), null, "testing");
		assertNotNull(db2);

	}
    
	@Test
	public void write() throws IOException, UnsupportedDataBaseException, KeePassDataBaseException {
		KeePassDataBase keePassDb = KeePassDataBaseManager.openDataBase(new File(
					"testing-key.kdb"), new File("testing-key.key"), null);
		assertNotNull(keePassDb);
		KeePassDataBaseV1 kdb1 = (KeePassDataBaseV1) keePassDb;
	
		FileOutputStream fos = new FileOutputStream("testing-key-out.kdb");
		kdb1.write_copy_to_stream(fos);
	        fos.close();
        }

    	@Test
	public void writeKeyFilePasswordKdb() throws Exception {
		KeePassDataBase keePassDb = KeePassDataBaseManager.openDataBase(new File(
				"testing-pass-key.kdb"), new File("testing-key.key"), "testing");
		assertNotNull(keePassDb);
		KeePassDataBaseV1 kdb1 = (KeePassDataBaseV1) keePassDb; 
		FileOutputStream fos = new FileOutputStream("testing-pass-key-out.kdb");
		kdb1.write_copy_to_stream(fos);
		fos.close();
	}

	@Test 
	public void writeNew() throws IOException, KeePassDataBaseException {
		KeePassDataBaseV1 keePassDb = new KeePassDataBaseV1();
		keePassDb.setPassword("lalelu".getBytes());
		List<Group> groups = keePassDb.getGroups();
		List<Entry> entries = keePassDb.getEntries();
		
		Group g = new Group();
		Date now = new Date();
		g.set(1, "Peter", now, now, now, null, 
		      (short) 0, 0, null, null);
		
		groups.add(g);
		
		Entry e1 = new Entry();
		e1.set(1, null, "Entry 1", null, "user1", "pass1".getBytes(), null,
		       now, now, now, null, null, null, null);
		entries.add(e1);
		
		Entry e2 = new Entry();
		e2.set(1, null, "Entry 2", null, "user2", "pass2".getBytes(), null,
		       now, now, now, null, null, null, null);
		
		entries.add(e2);
				
		FileOutputStream fos = new FileOutputStream("creation-out.kdb");
		keePassDb.write_copy_to_stream(fos);
		fos.close();

	}
	
}