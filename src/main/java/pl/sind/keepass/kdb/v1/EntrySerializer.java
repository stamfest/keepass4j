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

/** @author Peter Stamfest */
public class EntrySerializer {
    public static int serialize(Entry e, ByteBuffer bb) {
	ArrayList<Field> allFields = new ArrayList<Field>();

	allFields.add(e.getUuid());
	allFields.add(e.getBinaryData());
	allFields.add(e.getBinaryDescription());
	allFields.add(e.getCreationTime());
	allFields.add(e.getExpirationTime());
	allFields.add(e.getGroupId());
	allFields.add(e.getImageId());
	allFields.add(e.getLastAccessTime());
	allFields.add(e.getLastModificationTime());
	allFields.add(e.getNotes());
	allFields.add(e.getPassword());
	allFields.add(e.getTitle());
	allFields.add(e.getUrl());
	allFields.add(e.getUsername());
	allFields.addAll(e.getComments());
	allFields.addAll(e.getUnknowns());
	
	return GroupSerializer.serializeFields(allFields, bb);
    }

}
