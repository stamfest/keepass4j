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

package pl.sind.keepass.kdb.v1;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

/**
 *
 * @author peter
 */
public class GroupSerializer {
    public static int serialize(Group g, ByteBuffer bb) {
	ArrayList<Field> allFields = getAllFields(g);
	
	return serializeFields(allFields, bb);
    }

    public static int serializeFields(ArrayList<Field> allFields, ByteBuffer bb) {
	Collections.sort(allFields, new Comparator<Field>() {
	    public int compare(Field o1, Field o2) {
		if (o1 == null && o2 == null) return 0;
		if (o1 == null) return 1;
		if (o2 == null) return -1;
		
		return o1.getFieldType() - o2.getFieldType();
	    }
	});
	
	int total_length = 0;
	for (Field f : allFields) {
	    if (f == null) continue;
	    
	    total_length += 2; // space for field type
	    total_length += 4; // space for field length
	    total_length += f.getFieldSize();
	    
	    int addlen = 0;
	    if (f instanceof TextField) {
		// strings are nul terminated!!!  WHAT A HACK in the original code
		total_length += 1;
		addlen = 1;
	    }
	    
	    if (bb == null) continue;
	    
	    bb.putShort(f.getFieldType());
	    bb.putInt(f.getFieldSize() + addlen);
	    bb.put(f.getFieldData());
   	    if (f instanceof TextField) {
		bb.put((byte) 0);
	    }

	}
	// termination...
	total_length += 2;
	total_length += 4;
	if (bb != null) {
	    bb.putShort((short)-1);
	    bb.putInt(0);
	}
	return total_length;
    }

    public static ArrayList<Field> getAllFields(Group g) {
	ArrayList<Field> allFields = new ArrayList<Field>();
	allFields.add(g.getGroupId());
	allFields.add(g.getGroupName());
	allFields.add(g.getCreationTime());
	allFields.add(g.getLastModificationTime());
	allFields.add(g.getLastAccessTime());
	allFields.add(g.getExpirationTime());
	allFields.add(g.getImage());
	allFields.add(g.getLevel());
	allFields.add(g.getFlags());
	allFields.addAll(g.getComments());
	allFields.addAll(g.getUnknowns());
	return allFields;
    }
}
