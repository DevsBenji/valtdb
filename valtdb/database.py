import os
import json
from typing import Dict, List, Any
from .table import Table
from .exceptions import ValtDBError
from .keypair import KeyPair
from .crypto import encrypt_data, decrypt_data

class Database:
    def __init__(self, name: str, path: str = ".", keypair: KeyPair = None):
        """Initialize database with name and path."""
        self.name = name
        self.path = path
        self.filename = os.path.join(path, f"{name}.valt")
        self.tables: Dict[str, Table] = {}
        self.keypair = keypair
        self._load_or_create()

    def _load_or_create(self):
        """Load existing database or create new one."""
        if os.path.exists(self.filename):
            self._load()
        else:
            self._create()

    def _load(self):
        """Load database from file."""
        try:
            with open(self.filename, 'rb') as f:
                encrypted_data = f.read()
                if self.keypair:
                    data = decrypt_data(encrypted_data, self.keypair.private_key)
                else:
                    data = json.loads(encrypted_data.decode())
                
                for table_name, table_data in data.items():
                    self.tables[table_name] = Table(table_name, table_data, self.keypair)
        except Exception as e:
            raise ValtDBError(f"Failed to load database: {str(e)}")

    def _create(self):
        """Create new database file."""
        try:
            empty_data = {}
            if self.keypair:
                encrypted_data = encrypt_data(empty_data, self.keypair.public_key)
            else:
                encrypted_data = json.dumps(empty_data).encode()
            
            with open(self.filename, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            raise ValtDBError(f"Failed to create database: {str(e)}")

    def create_table(self, name: str, schema: Dict[str, str]) -> Table:
        """Create new table with specified schema."""
        if name in self.tables:
            raise ValtDBError(f"Table {name} already exists")
        
        table = Table(name, {"schema": schema, "data": []}, self.keypair)
        self.tables[name] = table
        self._save()
        return table

    def get_table(self, name: str) -> Table:
        """Get table by name."""
        if name not in self.tables:
            raise ValtDBError(f"Table {name} does not exist")
        return self.tables[name]

    def drop_table(self, name: str):
        """Drop table by name."""
        if name not in self.tables:
            raise ValtDBError(f"Table {name} does not exist")
        del self.tables[name]
        self._save()

    def _save(self):
        """Save database to file."""
        try:
            data = {name: table.to_dict() for name, table in self.tables.items()}
            
            if self.keypair:
                encrypted_data = encrypt_data(data, self.keypair.public_key)
            else:
                encrypted_data = json.dumps(data).encode()
            
            with open(self.filename, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            raise ValtDBError(f"Failed to save database: {str(e)}")

    def list_tables(self) -> List[str]:
        """List all tables in database."""
        return list(self.tables.keys())
