package pl.sind.keepass.kdb.v1;

import java.nio.ByteBuffer;

import pl.sind.keepass.util.Utils;

public class LevelField extends Field {

	public LevelField(short fieldType, int fieldSize, ByteBuffer data) {
		super(fieldType, fieldSize, LEVEL_FIELD_SIZE, data);
	}

	public void setLevel(short value) {
		Utils.shortTobytes(value,getFieldData());
	}

	public short getLevel() {
		return Utils.bytesToShort(getFieldData());
	}
}
