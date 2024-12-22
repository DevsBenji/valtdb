Welcome to ValtDB's documentation!
================================

ValtDB is a secure and flexible database library for Python that provides encrypted data storage, remote access capabilities, and comprehensive authentication and authorization features.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   quickstart
   database
   schema
   query
   ssh
   auth
   cli
   api
   security
   contributing

Features
--------

Core Database
~~~~~~~~~~~~
* Encrypted data storage with RSA and SHA256
* Schema validation and type checking
* Advanced query system with filtering and sorting
* Indexing for fast data retrieval
* Data integrity verification

Security
~~~~~~~~
* Field-level encryption
* Password hashing with bcrypt
* JWT token-based authentication
* Role-Based Access Control (RBAC)
* Permission management
* Token blacklisting

Remote Access
~~~~~~~~~~~~
* Secure SSH connections
* Key-based authentication
* SFTP file transfer
* Remote database operations
* Connection pooling

Query System
~~~~~~~~~~~
* Complex filtering conditions
* Multiple sorting options
* Pagination support
* Aggregation functions
* Group by operations

Installation
------------

To install ValtDB, run this command in your terminal:

.. code-block:: console

    $ pip install valtdb

Quick Start
----------

Here's a simple example to get you started:

.. code-block:: python

    from valtdb import Database
    from valtdb.schema import Schema, SchemaField, DataType
    from valtdb.query import Query, Operator

    # Create schema
    schema = Schema([
        SchemaField("id", DataType.INT, unique=True),
        SchemaField("name", DataType.STR),
        SchemaField("salary", DataType.ENCRYPTED_FLOAT)
    ])

    # Create database
    db = Database("mydb", keypair=keypair)
    users = db.create_table("users", schema)

    # Insert data
    users.insert({
        "id": 1,
        "name": "John",
        "salary": 50000.0
    })

    # Query data
    results = users.select(
        Query()
        .filter("salary", Operator.GT, 40000)
        .sort("name")
    )

For more examples and detailed documentation, see the :doc:`quickstart` guide.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
