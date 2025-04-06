from pydantic import BaseModel, Field
from bson import ObjectId
from typing import Dict, Any
from typing import Optional

class VulnItem(BaseModel):
    ip: str
    OS: str
    vuln_FTPPortOpen : str
    vuln_FTPAccess : str
    vuln_SSHBruteforce : str
    vuln_TelnetPortOpen: str
    vuln_WebServerHTTPSQLi: str
    vuln_WebServerHTTPXSS: str

    _id: Optional[str] = Field(default=None, alias="_id")

    class Config:
        json_encoders = {
            ObjectId: str  # Convert ObjectId to string
        }

class UpdateRequest(BaseModel):
    ip: str
    update_field: str
    new_value: str

class jsvalue(BaseModel):
    value: str

