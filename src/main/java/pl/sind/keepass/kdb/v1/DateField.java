package pl.sind.keepass.kdb.v1;

import java.nio.ByteBuffer;
import java.util.Date;

import pl.sind.keepass.util.Utils;

public class DateField extends Field {

	public DateField(short fieldType, int fieldSize, ByteBuffer data) {
		super(fieldType, fieldSize,DATE_FIELD_SIZE, data);
	}

	public Date getDate(){
		return Utils.unpackDate(getFieldData());
	}
	
	public void setDate(Date date){
		setFieldData(Utils.packDate(date));
	}
	
}
