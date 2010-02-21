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
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Date;

import pl.sind.keepass.util.Utils;


public class EntryBuilder {
    private String uuid;
    private int groupId;
    private String title;
    private String url;
    private String username;
    private String password;
    private String notes;
    private Date creationTime;
    private Date lastModificationTime;
    private Date lastAccessTime;
    private Date expirationTime;
    private String binaryDescription;
    private byte[] binaryData;

    private byte[] packedDate = new byte[5];

    public void readField(short fieldType, int fieldSize, ByteBuffer data) throws UnsupportedEncodingException {
        byte[] fieldData;
        switch (fieldType) {
            case 0x0000: // Invalid or comment block, block is ignored
                break;
            case 0x0001: // UUID, uniquely identifying an entry, FIELDSIZE must be 16
                assertFieldSize(16, fieldSize);
                fieldData = new byte[fieldSize];
                data.get(fieldData);
                this.uuid = Utils.toHexString(fieldData);
                break;
            case 0x0002: // Group ID, identifying the group of the entry, FIELDSIZE = 4; It can be any 32-bit value except 0 and 0xFFFFFFFF
                assertFieldSize(4, fieldSize);
                this.groupId = data.getInt();
                break;
            case 0x0003: // Image ID, identifying the image/icon of the entry, FIELDSIZE = 4
                assertFieldSize(4, fieldSize);
                data.getInt();
                break;
            case 0x0004: // Title of the entry, FIELDDATA is an UTF-8 encoded string
                fieldData = new byte[fieldSize];
                data.get(fieldData);
                this.title = new String(fieldData, 0, fieldData.length - 1, "utf8");
                break;
            case 0x0005: // URL string, FIELDDATA is an UTF-8 encoded string
                fieldData = new byte[fieldSize];
                data.get(fieldData);
                this.url = new String(fieldData, 0, fieldData.length - 1, "utf8");
                break;
            case 0x0006: // UserName string, FIELDDATA is an UTF-8 encoded string
                fieldData = new byte[fieldSize];
                data.get(fieldData);
                this.username = new String(fieldData, 0, fieldData.length - 1, "utf8");
                break;
            case 0x0007: // Password string, FIELDDATA is an UTF-8 encoded string
                fieldData = new byte[fieldSize];
                data.get(fieldData);
                this.password = new String(fieldData, 0, fieldData.length - 1, "utf8");
                break;
            case 0x0008: // Notes string, FIELDDATA is an UTF-8 encoded string
                fieldData = new byte[fieldSize];
                data.get(fieldData);
                this.notes = new String(fieldData, 0, fieldData.length - 1, "utf8");
                break;
            case 0x0009: // Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
                assertFieldSize(5, fieldSize);
                data.get(packedDate);
                this.creationTime = Utils.unpackDate(packedDate);
                break;
            case 0x000A: // Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
                assertFieldSize(5, fieldSize);
                data.get(packedDate);
                this.lastModificationTime = Utils.unpackDate(packedDate);
                break;
            case 0x000B: // Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
                assertFieldSize(5, fieldSize);
                data.get(packedDate);
                this.lastAccessTime = Utils.unpackDate(packedDate);
                break;
            case 0x000C: // Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
                assertFieldSize(5, fieldSize);
                data.get(packedDate);
                this.expirationTime = Utils.unpackDate(packedDate);
                break;
            case 0x000D: // Binary description UTF-8 encoded string
                fieldData = new byte[fieldSize];
                data.get(fieldData);
                this.binaryDescription = new String(fieldData, 0, fieldData.length - 1, "utf8");
                break;
            case 0x000E: // Binary data
                this.binaryData = new byte[fieldSize];
                data.get(this.binaryData);
                break;
            default: // Entry terminator, FIELDSIZE must be 0
            	System.out.println(">>> fieldType: "+fieldType);
            	System.out.println(">>> fieldSize: "+fieldSize);
                break;
        }
    }

    private static void assertFieldSize(int expected, int provided) {
        if (expected != provided) {
            throw new IllegalArgumentException("Invalid field size: " + provided);
        }
    }

    public Entry buildEntry() {
        Entry toReturn = new Entry();
        toReturn.setUuid(this.uuid);
        toReturn.setGroupId(this.groupId);
        toReturn.setTitle(this.title);
        toReturn.setUrl(this.url);
        toReturn.setUsername(this.username);
        toReturn.setPassword(this.password);
        toReturn.setNotes(this.notes);
        toReturn.setCreationTime(this.creationTime);
        toReturn.setLastAccessTime(this.lastAccessTime);
        toReturn.setLastModificationTime(this.lastModificationTime);
        toReturn.setExpirationTime(this.expirationTime);
        toReturn.setBinaryDescription(this.binaryDescription);
        toReturn.setBinaryData(this.binaryData);
        return toReturn;
    }

}
