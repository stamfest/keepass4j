package pl.sind.keepass.kdb.v1;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

public class TextField extends Field {

	private static final Charset CHARSET = Charset.forName("UTF-8");
	
	public TextField(short fieldType, int fieldSize, ByteBuffer data) {
		// Strings are null terminated, remove 1 from size and remove from buffer
		super(fieldType, fieldSize-1,fieldSize-1, data);
		data.get();
	}
	
	public String getText() {
		return new String(getFieldData(),CHARSET);
	}

	public void setText(String text) {
		setFieldData(text.getBytes(CHARSET));
	}

}
