from app import app, db, User, SiteSettings, Service, Testimonial, Client, BlogCategory, BlogTag
from datetime import datetime

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✅ Database tables created successfully!")
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@incrediblestudios.com',
                role='super_admin',
                is_active=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            print("✅ Admin user created - username: admin, password: admin123, role: super_admin")
        else:
            # Update existing admin to super_admin if role is missing
            if not admin.role:
                admin.role = 'super_admin'
                admin.is_active = True
                db.session.commit()
                print("✅ Updated existing admin to super_admin role")
        
        # Check if settings exist
        settings = SiteSettings.query.first()
        if not settings:
            settings = SiteSettings()
            db.session.add(settings)
            print("✅ Site settings created")
        
        # Add sample blog category if none exist
        if BlogCategory.query.count() == 0:
            category = BlogCategory(name='Uncategorized', slug='uncategorized', description='Default category for blog posts')
            db.session.add(category)
            print("✅ Sample blog category created")
        
        db.session.commit()
        print("\n" + "="*50)
        print("Database initialization complete!")
        print("="*50)
        print("\nAdmin Login:")
        print("  Username: admin")
        print("  Password: admin123")
        print("  Role: super_admin")
        print("\nRun 'python app.py' to start the application")

if __name__ == '__main__':
    init_database()