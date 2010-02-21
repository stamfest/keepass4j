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

import java.util.Date;


public class Group {
    private int groupId;
    private String groupName;
    private Date creationTime;
    private Date lastModificationTime;
    private Date lastAccessTime;
    private Date expirationTime;
    private short level;

    public int getGroupId() {
        return groupId;
    }

    protected void setGroupId(int groupId) {
        this.groupId = groupId;
    }

    public String getGroupName() {
        return groupName;
    }

    protected void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    public Date getCreationTime() {
        return creationTime;
    }

    protected void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    public Date getLastModificationTime() {
        return lastModificationTime;
    }

    protected void setLastModificationTime(Date lastModificationTime) {
        this.lastModificationTime = lastModificationTime;
    }

    public Date getLastAccessTime() {
        return lastAccessTime;
    }

    protected void setLastAccessTime(Date lastAccessTime) {
        this.lastAccessTime = lastAccessTime;
    }

    public Date getExpirationTime() {
        return expirationTime;
    }

    protected void setExpirationTime(Date expirationTime) {
        this.expirationTime = expirationTime;
    }

    public short getLevel() {
        return level;
    }

    protected void setLevel(short level) {
        this.level = level;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("id=").append(Integer.toHexString(this.groupId));
        sb.append(", ");
        sb.append("lvl=").append(this.level);
        sb.append(", ");
        sb.append("name=").append(this.groupName);
        sb.append(", ");
        sb.append("created=[").append(this.creationTime).append(']');
        sb.append('}');
        return sb.toString();
    }
}
