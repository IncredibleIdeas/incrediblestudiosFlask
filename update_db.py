# update_db.py
from app import app, db, SiteSettings
import sqlite3
import os

def update_database():
    """Add missing columns to the site_settings table"""
    db_path = os.path.join('instance', 'incredible.db')
    
    if not os.path.exists(db_path):
        print("Database not found. Run init_db.py first.")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check existing columns
    cursor.execute("PRAGMA table_info(site_settings)")
    existing_columns = [col[1] for col in cursor.fetchall()]
    
    # New columns to add (based on the error)
    new_columns = {
        'since_year': "VARCHAR(20) DEFAULT '2015'",
        'hero_title_prefix': "VARCHAR(100) DEFAULT 'Your Vision,'",
        'hero_title_highlight': "VARCHAR(100) DEFAULT 'Reimagined'",
        'hero_description': "VARCHAR(300) DEFAULT 'We transform ideas into stunning digital experiences that captivate audiences and drive results.'",
        'hero_button_text': "VARCHAR(50) DEFAULT 'Get Started'",
        'hero_button2_text': "VARCHAR(50) DEFAULT 'View Work'",
        'hero_badge_text': "VARCHAR(50) DEFAULT 'Since 2015'",
        'clients_title': "VARCHAR(200) DEFAULT 'Trusted by innovative brands worldwide'",
        'services_badge': "VARCHAR(100) DEFAULT 'What We Offer'",
        'services_title': "VARCHAR(200) DEFAULT 'Our Creative Services'",
        'services_subtitle': "VARCHAR(300) DEFAULT 'Comprehensive solutions tailored to bring your brand to life in the digital world.'",
        'portfolio_badge': "VARCHAR(100) DEFAULT 'Our Work'",
        'portfolio_title': "VARCHAR(200) DEFAULT 'Featured Projects'",
        'portfolio_subtitle': "VARCHAR(300) DEFAULT 'A selection of our recent work that showcases our creativity and expertise.'",
        'testimonials_badge': "VARCHAR(100) DEFAULT 'Client Love'",
        'testimonials_title': "VARCHAR(200) DEFAULT 'What Our Clients Say'",
        'testimonials_subtitle': "VARCHAR(300) DEFAULT 'Don\'t just take our word for it - hear from the brands we\'ve helped transform.'",
        'cta_title': "VARCHAR(200) DEFAULT 'Ready to Bring Your Vision to Life?'",
        'cta_description': "VARCHAR(300) DEFAULT 'Let\'s create something incredible together. Get in touch with our team to discuss your project.'",
        'cta_button_text': "VARCHAR(50) DEFAULT 'Start Your Project'",
        'cta_button2_text': "VARCHAR(50) DEFAULT 'Call Us Now'",
        'footer_copyright': "VARCHAR(200) DEFAULT 'All rights reserved.'",
        'contact_hours': "VARCHAR(200) DEFAULT 'Monday - Friday: 9:00 AM - 6:00 PM PST'",
        'about_title': "VARCHAR(200) DEFAULT 'Crafting Digital Excellence'",
        'about_description': "TEXT DEFAULT 'Founded in 2015, Incredible Studios began as a small team of passionate designers and developers with a shared vision: to create digital experiences that not only look beautiful but also deliver real results for our clients.'",
        'about_description2': "TEXT DEFAULT 'Today, we\'ve grown into a full-service creative agency, but our core philosophy remains the same. We believe in the power of design to transform businesses and the importance of building meaningful relationships with our clients.'",
        'projects_count': "VARCHAR(20) DEFAULT '50+'",
        'projects_label': "VARCHAR(100) DEFAULT 'Projects Completed'",
        'clients_count': "VARCHAR(20) DEFAULT '30+'",
        'clients_label': "VARCHAR(100) DEFAULT 'Happy Clients'",
    }
    
    # Add missing columns
    for col_name, col_type in new_columns.items():
        if col_name not in existing_columns:
            try:
                cursor.execute(f"ALTER TABLE site_settings ADD COLUMN {col_name} {col_type}")
                print(f"Added column: {col_name}")
            except Exception as e:
                print(f"Error adding {col_name}: {e}")
    
    conn.commit()
    conn.close()
    print("Database update completed!")

if __name__ == '__main__':
    update_database()