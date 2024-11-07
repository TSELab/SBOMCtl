import sqlite3
import configparser
from sqlalchemy import MetaData
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from petra.models import tree_from_nodes


def get_session():
    """
    Create and return a new SQLAlchemy session for the PetraSBOMs database.

    This function initializes the database engine, creates all tables defined in the 
    Base metadata, and returns a session object for interacting with the database.

    Returns:
    Session: A new SQLAlchemy session object bound to the PetraSBOMs database.

    Usage:
    session = get_session()
    """
    config = configparser.ConfigParser()
    config.read('config.ini')
    database_url = config['database']['url']
    try:
        engine = create_engine(database_url) 
        Base.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        session = SessionLocal()   
        return session
    except Exception as e:
        print(f"Error creating database session: {e}")
        raise
Base = declarative_base()
class SBOM(Base):
    """
    Represents a Software Bill of Materials (SBOM) in the database.

    Attributes:
    id (int): The primary key identifier for the SBOM record.
    name (str): The unique name of the SBOM. Cannot be null.
    root_hash (str): The root hash of the SBOM. Cannot be null.
    created_at (datetime): The timestamp when the SBOM record was created.
    """
    __tablename__ = 'sbom'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False,unique=True)
    root_hash = Column(String, nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())

class SMTNode(Base):
    """
    Represents a node in a Sparse Merkle Tree (SMT) associated with a Software Bill of Materials (SBOM).

    Attributes:
    sbom_id (int): The foreign key identifier linking to the SBOM.
    key (str): The unique key for the SMT node. Cannot be null.
    value (str): The value associated with the SMT node. Cannot be null.
    """
    __tablename__ = 'smt_nodes'
    sbom_id = Column(Integer, ForeignKey('sbom.id'))
    key = Column(String, nullable=False,primary_key=True)
    value = Column(String, nullable=False)
    #parent_hash = Column(String)

class SMTValue(Base):
    """
    Represents a value in the Sparse Merkle Tree (SMT) associated with a Software Bill of Materials (SBOM).

    Attributes:
        sbom_id (int): The foreign key identifier linking to the SBOM.
        key (str): The unique key for the SMT value. Cannot be null.
        value (str): The value associated with the SMT value. Cannot be null.
    """
    __tablename__ = 'smt_values'
    sbom_id = Column(Integer, ForeignKey('sbom.id'))
    key = Column(String, nullable=False,primary_key=True)
    value = Column(String, nullable=False)
    #parent_hash = Column(String)


def store_SBOM_as_tree_in_db(tree_to_store, sbom_name):
    """
    Store the Sparse Merkle Tree representation of an SBOM in the database.

    Parameters:
        session (Session): The SQLAlchemy session to use for database operations.
        tree_to_store (SparseMerkleTree): The Sparse Merkle Tree to store.
        sbom_name (str): The name of the SBOM.
    """
    added_sbom=add_or_get_to_db(SBOM,name=sbom_name,root_hash=tree_to_store.root_as_bytes())
    session.flush()
    id = added_sbom.id
    for k,v in tree_to_store.store.nodes.items():
        added_node=add_or_get_to_db(SMTNode,sbom_id=id,key=k,value=v)
        session.flush()        
    for k,v in tree_to_store.store.values.items():
        added_value=add_or_get_to_db(SMTValue,sbom_id=id,key=k,value=v)
        session.flush()        

def add_or_get_to_db(table, **kwargs):
    """
    Add a new record to the database or return an existing record.

    Parameters:
        session (Session): The SQLAlchemy session to use.
        table (Base): The SQLAlchemy table class to query.
        **kwargs: The attributes to filter or create a new record.

    Returns:
        Base: The existing or newly created record.
    """
    # Try to find the record
    record = session.query(table).filter_by(**kwargs).first()
    if record:
        print(f"Record exists")
        return record
    else:
        new_record=table(**kwargs)
        # If it doesn't exist, create a new record
        session.add(new_record)
        session.commit()
        print(f"Record added")
        return new_record

def retrieve_sbom_as_tree_from_db(sbom_name):
    """
    Retrieve an SBOM as a Sparse Merkle Tree from the database.

    Parameters:
        session (Session): The SQLAlchemy session to use for database operations.
        sbom_name (str): The name of the SBOM to retrieve.

    Returns:
        SparseMerkleTree: The reconstructed Sparse Merkle Tree.
    """
    sbom = session.query(SBOM).filter_by(name=sbom_name).first()

    nodes=dict()
    values=dict()
    if sbom:
        print(sbom.id,sbom.name,sbom.root_hash)
        root=sbom.root_hash
    else:
        print(f"SBOM '{sbom_name}' not found.")
        return None
    smt_nodes = session.query(SMTNode).filter_by(sbom_id=sbom.id)
    smt_vals = session.query(SMTValue).filter_by(sbom_id=sbom.id)
    for response in smt_nodes.all():
        nodes[response.key]=response.value
        print(response.sbom_id,response.key,response.value)
    for response in smt_vals.all():
        values[response.key]=response.value
        print(response.sbom_id,response.key,response.value)

    retrieved_tree = tree_from_nodes(nodes, values, root)
    return retrieved_tree 
 
session = get_session()
