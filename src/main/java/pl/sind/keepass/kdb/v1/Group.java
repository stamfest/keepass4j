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

import java.util.List;



public class Group {
    private IdField groupId;
    private TextField groupName;
    private DateField creationTime;
    private DateField lastModificationTime;
    private DateField lastAccessTime;
    private DateField expirationTime;
    private LevelField level;
    private FlagsField flags;
    private List<Field> comments;
    private List<Field> unknowns;
    

	public Group(IdField groupId, TextField groupName, DateField creationTime,
			DateField lastModificationTime, DateField lastAccessTime,
			DateField expirationTime, LevelField level, FlagsField flags,
			List<Field> comments, List<Field> unknowns) {
		super();
		this.groupId = groupId;
		this.groupName = groupName;
		this.creationTime = creationTime;
		this.lastModificationTime = lastModificationTime;
		this.lastAccessTime = lastAccessTime;
		this.expirationTime = expirationTime;
		this.level = level;
		this.flags = flags;
		this.comments = comments;
		this.unknowns = unknowns;
	}

	public Group() {
		super();
	}

	public IdField getGroupId() {
		return groupId;
	}
	public void setGroupId(IdField groupId) {
		this.groupId = groupId;
	}
	public TextField getGroupName() {
		return groupName;
	}
	public void setGroupName(TextField groupName) {
		this.groupName = groupName;
	}
	public DateField getCreationTime() {
		return creationTime;
	}
	public void setCreationTime(DateField creationTime) {
		this.creationTime = creationTime;
	}
	public DateField getLastModificationTime() {
		return lastModificationTime;
	}
	public void setLastModificationTime(DateField lastModificationTime) {
		this.lastModificationTime = lastModificationTime;
	}
	public DateField getLastAccessTime() {
		return lastAccessTime;
	}
	public void setLastAccessTime(DateField lastAccessTime) {
		this.lastAccessTime = lastAccessTime;
	}
	public DateField getExpirationTime() {
		return expirationTime;
	}
	public void setExpirationTime(DateField expirationTime) {
		this.expirationTime = expirationTime;
	}
	public LevelField getLevel() {
		return level;
	}
	public void setLevel(LevelField level) {
		this.level = level;
	}
	public List<Field> getComments() {
		return comments;
	}
	public void setComments(List<Field> comments) {
		this.comments = comments;
	}
	public List<Field> getUnknowns() {
		return unknowns;
	}
	public void setUnknowns(List<Field> unknowns) {
		this.unknowns = unknowns;
	}
	
	public FlagsField getFlags() {
		return flags;
	}

	public void setFlags(FlagsField flags) {
		this.flags = flags;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((comments == null) ? 0 : comments.hashCode());
		result = prime * result
				+ ((creationTime == null) ? 0 : creationTime.hashCode());
		result = prime * result
				+ ((expirationTime == null) ? 0 : expirationTime.hashCode());
		result = prime * result + ((flags == null) ? 0 : flags.hashCode());
		result = prime * result + ((groupId == null) ? 0 : groupId.hashCode());
		result = prime * result
				+ ((groupName == null) ? 0 : groupName.hashCode());
		result = prime * result
				+ ((lastAccessTime == null) ? 0 : lastAccessTime.hashCode());
		result = prime
				* result
				+ ((lastModificationTime == null) ? 0 : lastModificationTime
						.hashCode());
		result = prime * result + ((level == null) ? 0 : level.hashCode());
		result = prime * result
				+ ((unknowns == null) ? 0 : unknowns.hashCode());
		return result;
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Group other = (Group) obj;
		if (comments == null) {
			if (other.comments != null) {
				return false;
			}
		} else if (!comments.equals(other.comments)) {
			return false;
		}
		if (creationTime == null) {
			if (other.creationTime != null) {
				return false;
			}
		} else if (!creationTime.equals(other.creationTime)) {
			return false;
		}
		if (expirationTime == null) {
			if (other.expirationTime != null) {
				return false;
			}
		} else if (!expirationTime.equals(other.expirationTime)) {
			return false;
		}
		if (flags == null) {
			if (other.flags != null) {
				return false;
			}
		} else if (!flags.equals(other.flags)) {
			return false;
		}
		if (groupId == null) {
			if (other.groupId != null) {
				return false;
			}
		} else if (!groupId.equals(other.groupId)) {
			return false;
		}
		if (groupName == null) {
			if (other.groupName != null) {
				return false;
			}
		} else if (!groupName.equals(other.groupName)) {
			return false;
		}
		if (lastAccessTime == null) {
			if (other.lastAccessTime != null) {
				return false;
			}
		} else if (!lastAccessTime.equals(other.lastAccessTime)) {
			return false;
		}
		if (lastModificationTime == null) {
			if (other.lastModificationTime != null) {
				return false;
			}
		} else if (!lastModificationTime.equals(other.lastModificationTime)) {
			return false;
		}
		if (level == null) {
			if (other.level != null) {
				return false;
			}
		} else if (!level.equals(other.level)) {
			return false;
		}
		if (unknowns == null) {
			if (other.unknowns != null) {
				return false;
			}
		} else if (!unknowns.equals(other.unknowns)) {
			return false;
		}
		return true;
	}
	@Override
	public String toString() {
		return "Group [groupId=" + groupId + ", groupName=" + groupName
				+ ", level=" + level + ", flags=" + flags + ", creationTime="
				+ creationTime + ", expirationTime=" + expirationTime
				+ ", lastAccessTime=" + lastAccessTime
				+ ", lastModificationTime=" + lastModificationTime
				+ ", comments=" + comments + ", unknowns=" + unknowns + "]";
	}

    
}
