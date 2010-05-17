package pl.sind.keepass.kdb.v1;

import java.nio.ByteBuffer;

import pl.sind.keepass.util.Utils;

public class FlagsField extends Field {

	public FlagsField(short fieldType, int fieldSize, ByteBuffer data) {
		super(fieldType, fieldSize, FLAGS_FIELD_SIZE, data);
	}

	public void setId(int value) {
		Utils.intTobytes(value,getFieldData());
	}

	public int getId() {
		return Utils.bytesToInt(getFieldData());
	}
}
