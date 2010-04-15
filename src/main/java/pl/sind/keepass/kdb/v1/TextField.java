package pl.sind.keepass.kdb.v1;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import pl.sind.keepass.util.Utils;

public class TextField extends Field {

	private static final Charset CHARSET = Charset.forName("UTF-8");
	
	public TextField(short fieldType, int fieldSize, ByteBuffer data) {
		super(fieldType, fieldSize,fieldSize, data);
	}
	
	public String getText() {
		return new String(getFieldData(),CHARSET);
	}

	public void setText(String text) {
		setFieldData(text.getBytes(CHARSET));
	}

}
