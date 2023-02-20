# define the database data and import details
import os

connection = {
    "uri": os.getenv("TYPEDB_HOST"),
    "port": os.getenv("TYPEDB_PORT"),
    "database": "oasis",
    "user": None,
    "password": None
}