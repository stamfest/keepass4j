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
package pl.sind.keepass.crypto;

import java.util.Arrays;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BcAESCipher implements pl.sind.keepass.crypto.Cipher {

	public byte[] decrypt(byte[] key, byte[] data, byte[] iv)
			throws CipherException {
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				new CBCBlockCipher(new AESEngine()));

		if (iv != null) {
			cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
		} else {
			cipher.init(false, new KeyParameter(key));
		}

		byte[] decoded = new byte[cipher.getOutputSize(data.length)];

		int out = cipher.processBytes(data, 0, data.length, decoded, 0);
		try {
			out += cipher.doFinal(decoded, out);

			if (out < decoded.length) {
				decoded = Arrays.copyOf(decoded, out);
			}

		} catch (DataLengthException e) {
			// we are padding so shouldn happen
			throw new CipherException("Invalid data lenght", e);
		} catch (IllegalStateException e) {
			throw new CipherException("Decrypting error", e);
		} catch (InvalidCipherTextException e) {
			throw new CipherException("Unable to decrypt data", e);
		}

		return decoded;

	}

	public byte[] encrypt(byte[] key, byte[] data, byte[] iv, int rounds,
			boolean padding) throws CipherException {
		BufferedBlockCipher cipher = null;

		if (padding) {
			cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(
					new AESEngine()));
		} else {
			cipher = new BufferedBlockCipher(new AESEngine());
		}

		if (iv != null) {
			cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
		} else {
			cipher.init(true, new KeyParameter(key));
		}

		byte[] encoded = null;
		if (padding) {
			encoded = new byte[cipher.getOutputSize(data.length)];
		} else {
			encoded = new byte[data.length];
		}

		int out = cipher.processBytes(data, 0, data.length, encoded, 0);
		if (rounds > 1) {
			for (int i = 1; i < rounds; i++) {
				out = cipher.processBytes(encoded, 0, encoded.length, encoded,
						0);
			}
		}

		try {
			if (padding && out < encoded.length)
				cipher.doFinal(encoded, out);
		} catch (DataLengthException e) {
			// we are padding so shouldn happen
			throw new CipherException("Invalid data lenght", e);
		} catch (IllegalStateException e) {
			throw new CipherException("Decrypting error", e);
		} catch (InvalidCipherTextException e) {
			throw new CipherException("Unable to decrypt data", e);
		}

		return encoded;
	}

	public String getId() {
		return Cipher.AES;
	}

}
