import logging
from pymongo import MongoClient, errors
from dotenv import load_dotenv
import os

class MongoDBHandler:
    def __init__(self, db_name="vuln"):
        load_dotenv()
        uri = os.getenv("MONGODB_URI")

        logging.basicConfig(
            filename="DB_logging.txt",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

        self.client = MongoClient(uri)
        self.db = self.client[db_name]
        self.collection_name = "vuln"
        
        # Create collection if it doesn't exist
        if self.collection_name not in self.db.list_collection_names():
            self.db.create_collection(self.collection_name)
            logging.info(f"Collection '{self.collection_name}' created.")
        
        self.collection = self.db[self.collection_name]
        logging.info("Connected to MongoDB and initialized collection.")

    def insert_data(self, data):
        """Insert a single document into the collection."""
        logging.info("Attempting to insert data.")
        try:
            result = self.collection.insert_one(data)
            logging.info(f"Data inserted successfully with ID: {result.inserted_id}")
            return result.inserted_id
        except errors.PyMongoError as e:
            logging.error(f"Insert Error: {e}")
            return None

    def insert_many(self, data_list):
        """Insert multiple documents into the collection."""
        logging.info("Attempting to insert multiple documents.")
        try:
            result = self.collection.insert_many(data_list)
            logging.info(f"Inserted multiple documents successfully with IDs: {result.inserted_ids}")
            return result.inserted_ids
        except errors.PyMongoError as e:
            logging.error(f"Insert Many Error: {e}")
            return None

    def find_data(self, query={}, projection=None):
        """Find documents in the collection based on a query."""
        logging.info(f"Attempting to find documents with query: {query}")
        try:
            documents = list(self.collection.find(query, projection))
            logging.info(f"Found {len(documents)} documents matching the query.")
            return documents
        except errors.PyMongoError as e:
            logging.error(f"Find Error: {e}")
            return []

    def update_one_field(self, filter_query, update_field, new_value):
        """
        Updates a single field in a document.
        
        :param filter_query: The filter to find the document.
        :param update_field: The field you want to update.
        :param new_value: The new value to assign to the field.
        :return: Result of the update operation (success or failure).
        """
        try:
            update_data = { "$set": { update_field: new_value } }
            result = self.collection.update_one(filter_query, update_data)
            if result.matched_count > 0:
                print(f"Successfully updated the document.")
                return True
            else:
                print(f"No document matched the filter.")
                return False
        except PyMongoError as e:
            print(f"Error updating the document: {e}")
            return False
        
    def get_all_data(self):
        """Return all documents in the collection as a list of dictionaries."""
        try:
            documents = list(self.collection.find())
            return documents
        except errors.PyMongoError as e:
            logging.error(f"Get All Data Error: {e}")
            return []

    def delete_data(self, query):
        """Delete documents in the collection based on a query."""
        logging.info(f"Attempting to delete documents with query: {query}")
        try:
            result = self.collection.delete_many(query)
            logging.info(f"Deleted {result.deleted_count} documents.")
            return result.deleted_count
        except errors.PyMongoError as e:
            logging.error(f"Delete Error: {e}")
            return 0

    def find_one(self, query={}, projection=None):
        """Find a single document in the collection."""
        logging.info(f"Attempting to find a single document with query: {query}")
        try:
            document = self.collection.find_one(query, projection)
            if document:
                logging.info("Document found.")
                return document
            else:
                logging.info("No document found with the given query.")
                return None
        except errors.PyMongoError as e:
            logging.error(f"Find One Error: {e}")
            return None

    def close_connection(self):
        """Close the MongoDB client connection."""
        logging.info("Closing MongoDB connection.")
        self.client.close()
        logging.info("MongoDB connection closed.")


# MongoDBHandler = MongoDBHandler()
# ip = "10.13.37.107"  # The IP you want to search for
# document = MongoDBHandler.find_one({"ip": ip})

# print(document)  # Print the result
        

