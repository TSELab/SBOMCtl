import sqlite3

from sqlalchemy import MetaData
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker


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
 
