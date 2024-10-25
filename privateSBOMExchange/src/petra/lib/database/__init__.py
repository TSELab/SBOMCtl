import sqlite3

from sqlalchemy import MetaData
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from petra.lib.models import tree_from_nodes


def get_session():
    # Create a database engine
    engine = create_engine('sqlite:///dfsddff.db')  # Use SQLite for this example

    # Create the table in the database
    Base.metadata.create_all(engine)

    # Create a session
    Session = sessionmaker(bind=engine)
    session = Session()   
    return session

Base = declarative_base()
class SBOM(Base):
        __tablename__ = 'sbom'
        
        id = Column(Integer, primary_key=True)
        name = Column(String, nullable=False,unique=True)
        root_hash = Column(String, nullable=False)
        created_at = Column(TIMESTAMP, server_default=func.now())

class SMTNode(Base):
        __tablename__ = 'smt_nodes'
        sbom_id = Column(Integer, ForeignKey('sbom.id'))
        key = Column(String, nullable=False,primary_key=True)
        value = Column(String, nullable=False)
        #parent_hash = Column(String)

class SMTValue(Base):
        __tablename__ = 'smt_values'
        sbom_id = Column(Integer, ForeignKey('sbom.id'))
        key = Column(String, nullable=False,primary_key=True)
        value = Column(String, nullable=False)
        #parent_hash = Column(String)


def store_SBOM_as_tree_in_db(tree_to_store, sbom_name):
  
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
    sbom = session.query(SBOM).filter_by(name=sbom_name).first()

    nodes=dict()
    values=dict()
    if sbom:
        print(sbom.id,sbom.name,sbom.root_hash)
        root=sbom.root_hash
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
