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
import java.util.Arrays;

public abstract class Field {
	public static final int DATE_FIELD_SIZE = 5;
	public static final int ID_FIELD_SIZE = 4;
	public static final int UUID_FIELD_SIZE = 16;

	private short fieldType;
	private int fieldSize;
	private byte[] fieldData;

	public Field(short fieldType, int fieldSize, int expectedFieldSize,
			ByteBuffer data) {
		super();
		if (fieldSize != expectedFieldSize) {
			throw new IllegalArgumentException(String.format(
					"Invalid field size for %s. Expecting %d found %d."
							, getClass().getSimpleName(), expectedFieldSize,
					fieldSize));
		}
		this.fieldType = fieldType;
		this.fieldSize = fieldSize;
		this.fieldData = new byte[fieldSize];
		data.get(fieldData);
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
