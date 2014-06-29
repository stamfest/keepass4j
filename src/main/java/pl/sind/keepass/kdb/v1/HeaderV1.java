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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import pl.sind.keepass.kdb.KeePassConst;

public class HeaderV1 {
    public static int LENGTH = 124;
    int dwSignature1;
    int dwSignature2;
    int dwFlags;
    int dwVersion;
    byte[] aMasterSeed;
    byte[] aEncryptionIV;
    int dwGroups;
    int dwEntries;
    byte[] aContentsHash;
    byte[] aMasterSeed2;
    int dwKeyEncRounds;

    public HeaderV1(ByteBuffer bb) {
        bb.rewind();
        dwSignature1 = bb.getInt();
        dwSignature2 = bb.getInt();
        dwFlags = bb.getInt();
        dwVersion = bb.getInt();
        bb.get(aMasterSeed = new byte[16]);
        bb.get(aEncryptionIV = new byte[16]);
        dwGroups = bb.getInt();
        dwEntries = bb.getInt();
        bb.get(aContentsHash = new byte[32]);
        bb.get(aMasterSeed2 = new byte[32]);
        dwKeyEncRounds = bb.getInt();
    }

    public HeaderV1() {
	dwSignature1 = KeePassConst.KDB_SIG_1;
	dwSignature2 = KeePassConst.KDB_SIG_2;
	dwFlags = KeePassConst.KDB_FLAG_SHA_2 | KeePassConst.KDB_FLAG_AES;
	dwVersion = KeePassConst.KDB_FILE_VERSION;

	dwGroups = 0;
	dwEntries = 0;

	SecureRandom sr = new SecureRandom();

	dwKeyEncRounds = sr.nextInt(0x10000);
    
	aMasterSeed = new byte[16];
	aEncryptionIV = new byte[16];
	aContentsHash = new byte[32];
	aMasterSeed2 = new byte[32];

	initSeeds(sr);
    }
    
    public byte[] getHeader() {
	ByteBuffer bb = ByteBuffer.allocate(LENGTH);
	bb.order(ByteOrder.LITTLE_ENDIAN);
	
	bb.putInt(dwSignature1);
	bb.putInt(dwSignature2);
	bb.putInt(dwFlags);
	bb.putInt(dwVersion);
	
	bb.put(aMasterSeed);
	bb.put(aEncryptionIV);
	bb.putInt(dwGroups);
	bb.putInt(dwEntries);
	
	bb.put(aContentsHash);
	bb.put(aMasterSeed2);
	
	bb.putInt(dwKeyEncRounds);
	
	return bb.array();
    }
    
    
    /* Tip: better pass a SecureRandom generator here. */
    public void initSeeds(Random sr) {
	sr.nextBytes(aMasterSeed);
	sr.nextBytes(aEncryptionIV);
	sr.nextBytes(aMasterSeed2);
    }
    
    public int getSignature1() {
        return dwSignature1;
    }

    public int getSignature2() {
        return dwSignature2;
    }

    public int getFlags() {
        return dwFlags;
    }

    public int getVersion() {
        return dwVersion;
    }

    public byte[] getMasterSeed() {
        return aMasterSeed;
    }

    public byte[] getEncryptionIV() {
        return aEncryptionIV;
    }

    public int getGroups() {
        return dwGroups;
    }

    public void setGroups(int g) {
	dwGroups = g;
    }
    
    public int getEntries() {
        return dwEntries;
    }

    public void setEntries(int e) {
	dwEntries = e;
    }
    
    public byte[] getContentsHash() {
        return aContentsHash;
    }

    public void setContentsHash(byte[] h) {
	aContentsHash = Arrays.copyOf(h, aContentsHash.length);
    }
    
    public byte[] getMasterSeed2() {
        return aMasterSeed2;
    }

    public int getKeyEncRounds() {
        return dwKeyEncRounds;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("dwVersion=").append(Integer.toHexString(this.dwVersion));
        sb.append(", ");
        sb.append("dwGroups=").append(this.dwGroups);
        sb.append(", ");
        sb.append("dwEntries=").append(this.dwEntries);
        sb.append(", ");
        sb.append("dwKeyEncRounds=").append(this.dwKeyEncRounds);
        sb.append('}');
        return sb.toString();
    }
}
