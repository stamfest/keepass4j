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
package pl.sind.keepass.kdb.v2;

import java.io.InputStream;
import java.nio.ByteBuffer;

import pl.sind.keepass.kdb.KeePassDataBase;

public class KeePassDataBaseV2 implements KeePassDataBase {

	public KeePassDataBaseV2(byte[] data, InputStream keyFile, String password) {
		super();
		throw new RuntimeException("Unimplemented yet.");
	}

	public void setKeyFile(InputStream keyFile) {
		// TODO Auto-generated method stub
		
	}

	public void setPassword(String password) {
		// TODO Auto-generated method stub
		
	}

}
