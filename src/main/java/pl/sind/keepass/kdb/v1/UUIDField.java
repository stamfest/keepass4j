package pl.sind.keepass.kdb.v1;

import java.nio.ByteBuffer;

import pl.sind.keepass.util.Utils;

public class UUIDField extends Field {

	public UUIDField(short fieldType, int fieldSize, ByteBuffer data) {
		super(fieldType, fieldSize, UUID_FIELD_SIZE, data);
	}

	public String getUuid() {
		return Utils.toHexString(getFieldData());
	}

	public void setUuid(String uuid) {
		if (uuid == null || uuid.length() != 32) {
			throw new IllegalArgumentException(
					"UUID has to be 32 characters long");
		}
		setFieldData(Utils.fromHexString(uuid));
	}

}
