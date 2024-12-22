"""
Command Line Interface for ValtDB
"""
import argparse
import sys
from typing import List
from .database import Database
from .crypto import generate_keypair, KeyPair
from .exceptions import ValtDBError

def create_parser() -> argparse.ArgumentParser:
    """Create command line parser"""
    parser = argparse.ArgumentParser(
        description="ValtDB - Fast and secure database with table support"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Create database
    create_parser = subparsers.add_parser("create", help="Create a new database")
    create_parser.add_argument("name", help="Database name")
    create_parser.add_argument("--path", default=".", help="Database path")
    create_parser.add_argument("--encrypted", action="store_true", help="Create encrypted database")
    
    # Generate keys
    keys_parser = subparsers.add_parser("generate-keys", help="Generate encryption keys")
    keys_parser.add_argument("--private", required=True, help="Private key file path")
    keys_parser.add_argument("--public", required=True, help="Public key file path")
    
    # Create table
    table_parser = subparsers.add_parser("create-table", help="Create a new table")
    table_parser.add_argument("db", help="Database name")
    table_parser.add_argument("table", help="Table name")
    table_parser.add_argument("--schema", required=True, help="Table schema (json format)")
    
    # List tables
    list_parser = subparsers.add_parser("list-tables", help="List all tables")
    list_parser.add_argument("db", help="Database name")
    
    return parser

def main(args: List[str] = None) -> int:
    """Main entry point"""
    if args is None:
        args = sys.argv[1:]
    
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    
    try:
        if parsed_args.command == "create":
            if parsed_args.encrypted:
                keypair = generate_keypair()
                db = Database(parsed_args.name, path=parsed_args.path, keypair=keypair)
                print(f"Created encrypted database: {parsed_args.name}")
            else:
                db = Database(parsed_args.name, path=parsed_args.path)
                print(f"Created database: {parsed_args.name}")
                
        elif parsed_args.command == "generate-keys":
            keypair = generate_keypair()
            with open(parsed_args.private, "wb") as f:
                f.write(keypair.private_key)
            with open(parsed_args.public, "wb") as f:
                f.write(keypair.public_key)
            print("Generated encryption keys")
            
        elif parsed_args.command == "create-table":
            import json
            db = Database(parsed_args.db)
            schema = json.loads(parsed_args.schema)
            db.create_table(parsed_args.table, schema)
            print(f"Created table: {parsed_args.table}")
            
        elif parsed_args.command == "list-tables":
            db = Database(parsed_args.db)
            tables = db.list_tables()
            if tables:
                print("\nTables:")
                for table in tables:
                    print(f"- {table}")
            else:
                print("No tables found")
                
        else:
            parser.print_help()
            return 1
            
    except ValtDBError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
