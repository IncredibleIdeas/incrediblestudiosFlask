# reset_db.py
import os
import sys

def reset_database():
    """Complete database reset"""
    db_path = os.path.join('instance', 'incredible.db')
    
    # Delete existing database
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Deleted old database")
    
    # Run init_db to create new database
    print("Creating new database...")
    os.system('python init_db.py')
    
    print("Database reset complete!")
    print("Run 'python app.py' to start the application")

if __name__ == '__main__':
    reset_database()