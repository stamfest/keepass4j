/*
 * Copyright 2009 Lukasz Wozniak
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

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import pl.sind.keepass.util.Utils;

public class GroupDeserializer {
    private IdField groupId;
    private TextField groupName;
    private DateField creationTime;
    private DateField lastModificationTime;
    private DateField lastAccessTime;
    private DateField expirationTime;
    private LevelField level;
    private FlagsField flags;
    private ArrayList<Field> comments = new ArrayList<Field>();
    private ArrayList<Field> unknowns = new ArrayList<Field>();

    public void readField(short fieldType, int fieldSize, ByteBuffer data) throws UnsupportedEncodingException {
        switch (fieldType) {
            case 0x0000: // Invalid or comment block
            	comments.add(new Field(fieldType,fieldSize,fieldSize, data));
                break;
            case 0x0001: // Group ID, FIELDSIZE must be 4 bytes; It can be any 32-bit value except 0 and 0xFFFFFFFF
                this.groupId = new IdField(fieldType, fieldSize, data);
                break;
            case 0x0002: // Group name, FIELDDATA is an UTF-8 encoded string
                this.groupName = new TextField(fieldType, fieldSize, data);
                break;
            case 0x0003: // Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
                this.creationTime = new DateField(fieldType, fieldSize, data);
                break;
            case 0x0004: // Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
                this.lastModificationTime =new DateField(fieldType, fieldSize, data);
                break;
            case 0x0005: // Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
                this.lastAccessTime = new DateField(fieldType, fieldSize, data);
                break;
            case 0x0006: // Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
                this.expirationTime = new DateField(fieldType, fieldSize, data);
                break;
            case 0x0007: // Image ID, FIELDSIZE must be 4 bytes
                data.getInt();
                break;
            case 0x0008: // Level, FIELDSIZE = 2
                this.level = new LevelField(fieldType, fieldSize, data);
                break;
            case 0x0009: // Flags, 32-bit value, FIELDSIZE = 4
                this.flags = new FlagsField(fieldType, fieldSize, data);
                break;
            default: // Group entry terminator, FIELDSIZE must be 0
            	unknowns.add(new Field(fieldType,fieldSize,fieldSize, data));
                break;
        }
    }


	public Group getGroup() {
		return new Group(groupId, groupName, creationTime,
				lastModificationTime, lastAccessTime, expirationTime, level,
				flags, comments, unknowns);
	}
	
	public void reset() {
		groupId = null;
		groupName = null;
		creationTime = null;
		lastModificationTime = null;
		lastAccessTime = null;
		expirationTime = null;
		level = null;
		flags = null;
		comments.clear();
		unknowns.clear();
	}
}
