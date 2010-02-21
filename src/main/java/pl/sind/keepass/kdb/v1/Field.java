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

import java.util.Arrays;

public class Field {
	private short fieldType;
	private int fieldSize;
	private byte[] fieldData;

	public Field(short fieldType, int fieldSize, byte[] fieldData) {
		super();
		this.fieldType = fieldType;
		this.fieldSize = fieldSize;
		this.fieldData = fieldData;
	}

	public short getFieldType() {
		return fieldType;
	}

	public void setFieldType(short fieldType) {
		this.fieldType = fieldType;
	}

	public int getFieldSize() {
		return fieldSize;
	}

	public void setFieldSize(int fieldSize) {
		this.fieldSize = fieldSize;
	}

	public byte[] getFieldData() {
		return fieldData;
	}

	public void setFieldData(byte[] fieldData) {
		this.fieldData = fieldData;
	}

	@Override
	public String toString() {
		return "Field [fieldData=" + Arrays.toString(fieldData)
				+ ", fieldSize=" + fieldSize + ", fieldType=" + fieldType + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(fieldData);
		result = prime * result + fieldSize;
		result = prime * result + fieldType;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Field other = (Field) obj;
		if (!Arrays.equals(fieldData, other.fieldData))
			return false;
		if (fieldSize != other.fieldSize)
			return false;
		if (fieldType != other.fieldType)
			return false;
		return true;
	}

}
