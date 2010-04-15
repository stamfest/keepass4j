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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;


public class Entry {
	
    private UUIDField uuid;
    private IdField groupId;
    private TextField title;
    private TextField url;
    private TextField username;
    private TextField password;
    private TextField notes;
    private DateField creationTime;
    private DateField lastModificationTime;
    private DateField lastAccessTime;
    private DateField expirationTime;
    private TextField binaryDescription;
    private BinnaryField binaryData;



	public Entry(UUIDField uuid, IdField groupId, TextField title,
			TextField url, TextField username, TextField password,
			TextField notes, DateField creationTime,
			DateField lastModificationTime, DateField lastAccessTime,
			DateField expirationTime, TextField binaryDescription,
			BinnaryField binaryData) {
		super();
		this.uuid = uuid;
		this.groupId = groupId;
		this.title = title;
		this.url = url;
		this.username = username;
		this.password = password;
		this.notes = notes;
		this.creationTime = creationTime;
		this.lastModificationTime = lastModificationTime;
		this.lastAccessTime = lastAccessTime;
		this.expirationTime = expirationTime;
		this.binaryDescription = binaryDescription;
		this.binaryData = binaryData;
	}

	public String getUuid() {
        return uuid.getUuid();
    }

    protected void setUuid(String uuid) {
        this.uuid.setUuid(uuid);
    }

    public int getGroupId() {
        return groupId.getId();
    }

    protected void setGroupId(int groupId) {
        this.groupId.setId(groupId);
    }

    public String getTitle() {
        return title.getText();
    }

    protected void setTitle(String title) {
        this.title.setText(title);
    }

    public String getUrl() {
        return url.getText();
    }

    protected void setUrl(String url) {
        this.url.setText(url);
    }

    public String getUsername() {
        return username.getText();
    }

    protected void setUsername(String username) {
        this.username.setText(username);
    }

    public String getPassword() {
        return password.getText();
    }

    protected void setPassword(String password) {
        this.password.setText(password);
    }

    public String getNotes() {
        return notes.getText();
    }

    protected void setNotes(String notes) {
        this.notes.setText(notes);
    }

    public Date getCreationTime() {
        return creationTime.getDate();
    }

    protected void setCreationTime(Date creationTime) {
        this.creationTime.setDate(creationTime);
    }

    public Date getLastModificationTime() {
        return lastModificationTime.getDate();
    }

    protected void setLastModificationTime(Date lastModificationTime) {
        this.lastModificationTime.setDate(lastModificationTime);
    }

    public Date getLastAccessTime() {
        return lastAccessTime.getDate();
    }

    protected void setLastAccessTime(Date lastAccessTime) {
        this.lastAccessTime.setDate(lastAccessTime);
    }

    public Date getExpirationTime() {
        return expirationTime.getDate();
    }

    protected void setExpirationTime(Date expirationTime) {
        this.expirationTime.setDate(expirationTime);
    }

    public String getBinaryDescription() {
        return binaryDescription.getText();
    }

    protected void setBinaryDescription(String binaryDescription) {
    	this.binaryDescription.setText(binaryDescription);
    }

    public byte[] getBinaryData() {
        return binaryData.getFieldData();
    }

    protected void setBinaryData(byte[] binaryData) {
        this.binaryData.setFieldData(binaryData);
        this.binaryData.setFieldSize(binaryData==null?0:binaryData.length);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("gid=").append(Integer.toHexString(this.groupId.getId()));
        sb.append(", ");
        sb.append("title=").append(this.title);
        sb.append(", ");
        sb.append("url=").append(this.url);
        sb.append(", ");
        sb.append("created=[").append(this.creationTime).append(']');
        sb.append('}');
        return sb.toString();
    }

}
