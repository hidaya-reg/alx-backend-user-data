#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from user import User, Base


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db")
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database and return the User object
        """
        new_user = User(email=email, hashed_password=hashed_password)
        try:
            self._session.add(new_user)
            self._session.commit()
        except Exception as e:
            print(f"Error adding user to database: {e}")
            self._session.rollback()
            raise
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by arbitrary keyword arguments
        """
        session = self._session
        try:
            user = session.query(User).filter_by(**kwargs).one()
        except NoResultFound:
            raise NoResultFound()
        except InvalidRequestError:
            raise InvalidRequestError()
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update user attributes based on provided keyword arguments.
        """
        user = self.find_user_by(id=user_id)
        valid_attributes = {column.name for column in User.__table__.columns}

        for key, value in kwargs.items():
            if key not in valid_attributes:
                raise ValueError(f"Invalid attribute: {key}")
            setattr(user, key, value)

        self._session.commit()
