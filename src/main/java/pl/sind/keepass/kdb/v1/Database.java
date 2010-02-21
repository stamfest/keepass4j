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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ByteChannel;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import pl.sind.keepass.State;
import pl.sind.keepass.util.Utils;


public class Database {

	private HeaderV1 header;
	private List<Group> groups;
	private List<Entry> entries;

	private State state = State.NEW;

	private int DB_VERSION = 0x00030002;

	private byte FLAG_SHA_2 = 0x1;
	private byte FLAG_AES = 0x2;
	private byte FLAG_ARC4 = 0x4;
	private byte FLAG_TWOFISH = 0x8;

	private BlockCipher aesEngine = new AESEngine();
	// private BlockCipher twofishEngine = new TwofishEngine();
	private File keyFile;
	private byte[] keyValue;
	private byte[] passwordHash;
	private File dbFile;
	MessageDigest sha256;

	public Database(File dbfile, File keyFile, String password)
			throws NoSuchAlgorithmException {
		sha256 = MessageDigest.getInstance("SHA-256");
		if (password != null && password.length() > 0) {
			passwordHash = sha256.digest(password.getBytes());
		}
		this.keyFile = keyFile;
		this.dbFile = dbfile;
	}

	public State getState() {
		return state;
	}

	public void setKeyFile(File keyFile) {
		this.keyFile = keyFile;
	}

	public void setPassword(String password) {
		if (password != null && password.length() > 0) {
			this.passwordHash = sha256.digest(password.getBytes());
		} else {
			passwordHash = null;
		}
	}

	public HeaderV1 getHeader() {
		return header;
	}

	public List<Group> getGroups() {
		return groups;
	}

	public List<Entry> getEntries() {
		return entries;
	}

	private void validateHeaderValues() throws IOException {
		if ((header.getVersion() & 0xFFFFFF00) != (DB_VERSION & 0xFFFFFF00)) {
			throw new IOException("Unsupproted version: "
					+ Integer.toHexString(this.header.getVersion()));
		}

		if ((header.getFlags() & FLAG_ARC4) == FLAG_ARC4) {
			throw new IOException("ARC4 is not supported");
		}

		if ((header.getFlags() & FLAG_TWOFISH) == FLAG_TWOFISH) {
			throw new IOException("TwoFish is not supported");
		}
	}

	public void decrypt(byte[] file) throws IOException, InvalidCipherTextException,
			NoSuchAlgorithmException {
		int pos=0;
		ByteBuffer content;
		
			ByteBuffer bb = ByteBuffer.wrap(file).order(
					ByteOrder.LITTLE_ENDIAN);
			
			this.header = new HeaderV1(bb);

			pos = bb.position();
			
			validateHeaderValues();

			content = ByteBuffer.allocate(file.length-pos).order(ByteOrder.LITTLE_ENDIAN);
			content.put(file, pos, file.length-pos);
			
		
			
		// decrypting content

		byte[] data = content.array();
		System.out.println(Utils.toHexString(data));;
		decryptContent(data);

		content.rewind();

		this.groups = new ArrayList<Group>();
		for (int i = 0; i < this.header.getGroups(); i++) {
			short fieldType;
			GroupBuilder builder = new GroupBuilder();
			while ((fieldType = content.getShort()) != -1) {
				if (fieldType == 0) {
					continue;
				}
				int fieldSize = content.getInt();
				builder.readField(fieldType, fieldSize, content);
			}
			content.getInt(); // reading FIELDSIZE of group entry terminator
			this.groups.add(builder.buildGroup());
		}

		this.entries = new ArrayList<Entry>();
		for (int i = 0; i < this.header.getEntries(); i++) {
			short fieldType;
			EntryBuilder builder = new EntryBuilder();
			while ((fieldType = content.getShort()) != -1) {
				if (fieldType == 0) {
					continue;
				}
				int fieldSize = content.getInt();
				builder.readField(fieldType, fieldSize, content);
			}
			content.getInt(); // reading FIELDSIZE of entry terminator
			this.entries.add(builder.buildEntry());
		}
		state = State.READY;
	}

	private void decryptContent(byte[] data) throws InvalidCipherTextException,
			IOException {

		byte[] finalKey = prepareCryptKey();
		System.out.println(Utils.toHexString(finalKey));
		// decrypt main data
		performAESDecrypt(finalKey, data);

		int idx = 1;
		while (data[data.length - idx] != 0) {
			idx++;
		}

		sha256.reset();
		sha256.update(data, 0, data.length - idx + 1);
		byte[] hash = new byte[32];
		// sha256.doFinal(hash, 0);
		hash = sha256.digest();

		if (!Arrays.equals(hash, this.header.getContentsHash())) {
			throw new IOException(
					"Decryption failed! Incorrect password and/or master key.");
		}
	}

	private byte[] getPasswordKey() throws IOException {
		byte[] passwordKey;
		if (keyFile == null) {
			passwordKey = passwordHash;
		} else if (passwordHash == null) {
			passwordKey = getKeyFileValue();
		} else {
			passwordKey = passwordHash;
			sha256.reset();
			sha256.update(passwordHash);
			sha256.update(getKeyFileValue());
			passwordKey = sha256.digest();
		}

		return passwordKey;
	}

	private byte[] getKeyFileValue() throws IOException {
		FileChannel channel = new FileInputStream(this.keyFile).getChannel();
		
		ByteBuffer bb = ByteBuffer.allocate((int) keyFile.length()).order(
				ByteOrder.LITTLE_ENDIAN);
		channel.read(bb);
		
		byte[] keyData = bb.array();
		if(keyData.length==32){
			return keyData;
		}else if(keyData.length==64){
			return Utils.fromHexString(new String(keyData));
		}else{
			sha256.reset();
			sha256.update(keyData);
			keyData = sha256.digest();
			return keyData; 
		}
		
	}

	private byte[] prepareCryptKey() throws IOException, DataLengthException,
			IllegalStateException, InvalidCipherTextException {
		byte[] passKey = getPasswordKey();

		KeyParameter masterSeed2 = new KeyParameter(this.header
				.getMasterSeed2());

		BufferedBlockCipher ecbCipher = new BufferedBlockCipher(this.aesEngine);
		ecbCipher.init(true, masterSeed2);

		byte[] result = new byte[passKey.length];

		for (int i = 0; i < this.header.getKeyEncRounds(); i++) {
			int outputLen = ecbCipher.processBytes(passKey, 0, passKey.length,
					result, 0);
			ecbCipher.doFinal(result, outputLen);
			System.arraycopy(result, 0, passKey, 0, passKey.length);
		}

		sha256.reset();
		sha256.update(passKey);
		passKey = sha256.digest();
		sha256.reset();
		sha256.update(header.getMasterSeed());
		sha256.update(passKey);
		return sha256.digest();
	}

	private void performAESDecrypt(byte[] key, byte[] data) throws IOException,
			InvalidCipherTextException {
		KeyParameter keyParameter = new KeyParameter(key);

		BufferedBlockCipher cbcCipher = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(this.aesEngine), new ZeroBytePadding());
		cbcCipher.init(false, new ParametersWithIV(keyParameter, this.header
				.getEncryptionIV()));

		byte[] result = new byte[data.length];
		int outputLen = cbcCipher.processBytes(data, 0, data.length, result, 0);
		cbcCipher.doFinal(result, outputLen);

		System.arraycopy(result, 0, data, 0, data.length);
	}

}
