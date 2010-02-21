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
package pl.sind.keepass.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import pl.sind.keepass.crypto.CipherException;

public class JdkSHA256Hash implements Hash {
	
	private MessageDigest sha256;
	
	public JdkSHA256Hash() throws CipherException{
		super();
		try {
			sha256 = MessageDigest.getInstance(Hash.SHA_256);
		} catch (NoSuchAlgorithmException e) {
			throw new CipherException("SHA-256 is not supported on this system.", e);
		}
	}

	public byte[] digest() {
		return sha256.digest();
	}

	public byte[] hash(byte[] data) {
		reset();
		update(data);
		return digest();
	}

	public void reset() {
		sha256.reset();
	}

	public void update(byte[] data) {
		sha256.update(data);
	}

	public String getId() {
		return Hash.SHA_256;
	}

	public void update(byte[] data, int offset, int lenght) {
		update(data, offset, lenght);
	}

}
