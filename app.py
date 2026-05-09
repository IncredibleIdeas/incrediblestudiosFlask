from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import json
from sqlalchemy import func
import secrets
from flask_mail import Mail, Message
from html import escape
import csv
from io import StringIO, BytesIO
import re
import hashlib
import hmac
import base64
from urllib.parse import urlencode

# Optional imports with fallbacks
try:
    from user_agents import parse
    HAS_USER_AGENTS = True
except ImportError:
    HAS_USER_AGENTS = False
    def parse(ua):
        class FakeUA:
            is_mobile = False
            is_tablet = False
            is_pc = True
            browser = type('obj', (object,), {'family': 'Unknown'})
            os = type('obj', (object,), {'family': 'Unknown'})
        return FakeUA()

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import pyotp
    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incredible.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@yourdomain.com')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
mail = Mail(app)

# ==================== HELPER FUNCTIONS ====================

def get_device_type(user_agent):
    if not HAS_USER_AGENTS:
        return 'Desktop'
    try:
        ua = parse(user_agent)
        if ua.is_mobile:
            return 'Mobile'
        elif ua.is_tablet:
            return 'Tablet'
        elif ua.is_pc:
            return 'Desktop'
        return 'Other'
    except:
        return 'Desktop'

def get_browser_name(user_agent):
    if not HAS_USER_AGENTS:
        return 'Unknown'
    try:
        ua = parse(user_agent)
        return ua.browser.family or 'Unknown'
    except:
        return 'Unknown'

def get_os_name(user_agent):
    if not HAS_USER_AGENTS:
        return 'Unknown'
    try:
        ua = parse(user_agent)
        return ua.os.family or 'Unknown'
    except:
        return 'Unknown'

def generate_2fa_secret():
    return secrets.token_hex(20)

def get_2fa_qr_code(secret, username):
    if not HAS_QRCODE:
        return None
    try:
        totp_uri = f"otpauth://totp/{username}?secret={secret}&issuer=IncredibleStudios"
        qr = qrcode.make(totp_uri)
        buffered = BytesIO()
        qr.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()
    except:
        return None

def verify_2fa(secret, token):
    if not HAS_PYOTP:
        return True
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    except:
        return False

def log_activity(user_id, action, details=None, ip_address=None, user_agent=None):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address or request.remote_addr,
        user_agent=user_agent or request.headers.get('User-Agent', '')[:300]
    )
    db.session.add(log)
    db.session.commit()

def check_admin_access():
    if not current_user.is_authenticated:
        return False
    return current_user.role in ['super_admin', 'editor']

def check_super_admin():
    return current_user.is_authenticated and current_user.role == 'super_admin'

# ==================== MODELS ====================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='viewer')
    is_active = db.Column(db.Boolean, default=True)
    two_factor_secret = db.Column(db.String(200))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    last_ip = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='activities')

class IpWhitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100), default='Incredible Studios')
    site_tagline = db.Column(db.String(200), default='Your Vision, Reimagined')
    logo_text = db.Column(db.String(100), default='Incredible')
    studio_text = db.Column(db.String(100), default='Studios')
    since_year = db.Column(db.String(20), default='2015')
    primary_color = db.Column(db.String(20), default='#6C63FF')
    secondary_color = db.Column(db.String(20), default='#00BFA6')
    footer_text = db.Column(db.String(200), default='Transforming visions into stunning digital experiences since 2015.')
    
    google_analytics_id = db.Column(db.String(100), default='')
    meta_description = db.Column(db.String(300), default='')
    meta_keywords = db.Column(db.String(300), default='')
    meta_author = db.Column(db.String(100), default='')
    robots_txt = db.Column(db.Text, default='User-agent: *\nAllow: /\nSitemap: https://yourdomain.com/sitemap.xml')
    
    hero_title_prefix = db.Column(db.String(100), default='Your Vision,')
    hero_title_highlight = db.Column(db.String(100), default='Reimagined')
    hero_description = db.Column(db.String(300), default='We transform ideas into stunning digital experiences that captivate audiences and drive results.')
    hero_button_text = db.Column(db.String(50), default='Get Started')
    hero_button2_text = db.Column(db.String(50), default='View Work')
    hero_image = db.Column(db.String(200), default='https://images.unsplash.com/photo-1551288049-bebda4e38f71?ixlib=rb-1.2.1&auto=format&fit=crop&w=1000&q=80')
    hero_badge_text = db.Column(db.String(50), default='Since 2015')
    
    clients_title = db.Column(db.String(200), default='Trusted by innovative brands worldwide')
    clients = db.Column(db.Text, default='["Brand 1", "Brand 2", "Brand 3", "Brand 4", "Brand 5"]')
    
    services_badge = db.Column(db.String(100), default='What We Offer')
    services_title = db.Column(db.String(200), default='Our Creative Services')
    services_subtitle = db.Column(db.String(300), default='Comprehensive solutions tailored to bring your brand to life in the digital world.')
    
    portfolio_badge = db.Column(db.String(100), default='Our Work')
    portfolio_title = db.Column(db.String(200), default='Featured Projects')
    portfolio_subtitle = db.Column(db.String(300), default='A selection of our recent work that showcases our creativity and expertise.')
    
    testimonials_badge = db.Column(db.String(100), default='Client Love')
    testimonials_title = db.Column(db.String(200), default='What Our Clients Say')
    testimonials_subtitle = db.Column(db.String(300), default="Don't just take our word for it - hear from the brands we've helped transform.")
    
    cta_title = db.Column(db.String(200), default='Ready to Bring Your Vision to Life?')
    cta_description = db.Column(db.String(300), default="Let's create something incredible together. Get in touch with our team to discuss your project.")
    cta_button_text = db.Column(db.String(50), default='Start Your Project')
    cta_button2_text = db.Column(db.String(50), default='Call Us Now')
    
    footer_copyright = db.Column(db.String(200), default='All rights reserved.')
    
    contact_email = db.Column(db.String(120), default='hello@incrediblestudios.com')
    contact_phone = db.Column(db.String(50), default='+1 (234) 567-890')
    contact_address = db.Column(db.String(200), default='123 Design Street, Creative City, CA 90210')
    contact_hours = db.Column(db.String(200), default='Monday - Friday: 9:00 AM - 6:00 PM PST')
    
    about_image = db.Column(db.String(200), default='https://images.unsplash.com/photo-1522071820081-009f0129c71c?ixlib=rb-1.2.1&auto=format&fit=crop&w=1000&q=80')
    about_title = db.Column(db.String(200), default='Crafting Digital Excellence')
    about_description = db.Column(db.Text, default='Founded in 2015, Incredible Studios began as a small team...')
    about_description2 = db.Column(db.Text, default='Today, we\'ve grown into a full-service creative agency...')
    projects_count = db.Column(db.String(20), default='50+')
    projects_label = db.Column(db.String(100), default='Projects Completed')
    clients_count = db.Column(db.String(20), default='30+')
    clients_label = db.Column(db.String(100), default='Happy Clients')

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon_name = db.Column(db.String(50), default='web')
    features = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)

class Testimonial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100))
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, default=5)
    image_url = db.Column(db.String(300))
    order = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    logo_url = db.Column(db.String(300))
    website = db.Column(db.String(200))
    order = db.Column(db.Integer, default=0)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(300))
    image_filename = db.Column(db.String(200))
    client = db.Column(db.String(100))
    year = db.Column(db.String(20))
    services = db.Column(db.String(200))
    description = db.Column(db.Text)
    challenge = db.Column(db.Text)
    approach = db.Column(db.Text)
    results = db.Column(db.Text)
    featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ContactSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    service = db.Column(db.String(100))
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class PageView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(300))
    referrer = db.Column(db.String(500))
    session_id = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Subscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100))
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    verification_token = db.Column(db.String(100), unique=True)
    is_verified = db.Column(db.Boolean, default=False)
    unsubscribed_at = db.Column(db.DateTime)

class NewsletterCampaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    html_content = db.Column(db.Text)
    status = db.Column(db.String(20), default='draft')
    sent_at = db.Column(db.DateTime)
    scheduled_for = db.Column(db.DateTime)
    total_sent = db.Column(db.Integer, default=0)
    total_opened = db.Column(db.Integer, default=0)
    total_clicked = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EmailTracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('newsletter_campaign.id'))
    subscriber_id = db.Column(db.Integer, db.ForeignKey('subscriber.id'))
    opened_at = db.Column(db.DateTime)
    clicked_at = db.Column(db.DateTime)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(300))

class EmailTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    html_content = db.Column(db.Text, nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== BLOG MODELS ====================

class BlogCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlogTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    excerpt = db.Column(db.Text)
    content = db.Column(db.Text, nullable=False)
    featured_image = db.Column(db.String(300))
    category_id = db.Column(db.Integer, db.ForeignKey('blog_category.id'))
    status = db.Column(db.String(20), default='draft')
    scheduled_for = db.Column(db.DateTime)
    published_at = db.Column(db.DateTime)
    views = db.Column(db.Integer, default=0)
    seo_title = db.Column(db.String(200))
    seo_description = db.Column(db.String(300))
    seo_keywords = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    author = db.relationship('User', backref='posts')
    category = db.relationship('BlogCategory', backref='posts')
    tags = db.relationship('BlogTag', secondary='blog_post_tags', backref='posts')

class BlogPostTag(db.Model):
    __tablename__ = 'blog_post_tags'
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('blog_tag.id'), primary_key=True)

class BlogComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)
    author_name = db.Column(db.String(100), nullable=False)
    author_email = db.Column(db.String(120), nullable=False)
    author_website = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    parent_id = db.Column(db.Integer, db.ForeignKey('blog_comment.id'))
    
    replies = db.relationship('BlogComment', backref=db.backref('parent', remote_side=[id]))
    post = db.relationship('BlogPost', backref='comments')

# ==================== NEWSLETTER ROUTES ====================

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    name = request.form.get('name', '')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'})
    
    existing = Subscriber.query.filter_by(email=email).first()
    if existing:
        if existing.is_active:
            return jsonify({'success': False, 'message': 'Email already subscribed!'})
        else:
            existing.is_active = True
            existing.unsubscribed_at = None
            db.session.commit()
            return jsonify({'success': True, 'message': 'Welcome back! You have been resubscribed.'})
    
    token = secrets.token_urlsafe(32)
    subscriber = Subscriber(
        email=email,
        name=name,
        verification_token=token,
        is_verified=False,
        is_active=True
    )
    db.session.add(subscriber)
    db.session.commit()
    
    send_verification_email(email, token, name)
    return jsonify({'success': True, 'message': 'Please check your email to confirm subscription!'})

def send_verification_email(email, token, name):
    verification_url = url_for('verify_subscription', token=token, _external=True)
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><style>
        body {{ font-family: Arial, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #6C63FF; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background: #f9f9f9; }}
        .button {{ background: #6C63FF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; }}
        .footer {{ text-align: center; padding: 20px; color: #666; }}
    </style></head>
    <body>
        <div class="container">
            <div class="header"><h2>Confirm Your Subscription</h2></div>
            <div class="content">
                <p>Hello {escape(name) if name else 'there'}!</p>
                <p>Thank you for subscribing. Please click the button below to confirm:</p>
                <p style="text-align: center;"><a href="{verification_url}" class="button">Confirm Subscription</a></p>
                <p>If you didn't sign up, please ignore this email.</p>
            </div>
            <div class="footer"><p>&copy; 2025 Incredible Studios. All rights reserved.</p></div>
        </div>
    </body>
    </html>
    '''
    msg = Message('Confirm your subscription', recipients=[email])
    msg.html = html
    mail.send(msg)

@app.route('/verify/<token>')
def verify_subscription(token):
    subscriber = Subscriber.query.filter_by(verification_token=token).first()
    if not subscriber:
        flash('Invalid verification link.', 'error')
        return redirect(url_for('index'))
    
    subscriber.is_verified = True
    subscriber.verification_token = None
    db.session.commit()
    send_welcome_email(subscriber.email, subscriber.name)
    flash('Email verified successfully! Welcome to our newsletter!', 'success')
    return redirect(url_for('index'))

def send_welcome_email(email, name):
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><style>
        body {{ font-family: Arial, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #6C63FF; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background: #f9f9f9; }}
        .footer {{ text-align: center; padding: 20px; color: #666; }}
    </style></head>
    <body>
        <div class="container">
            <div class="header"><h2>Welcome to Incredible Studios!</h2></div>
            <div class="content">
                <p>Hello {escape(name) if name else 'there'}!</p>
                <p>Thank you for confirming your subscription. You'll now receive our latest news and exclusive offers.</p>
                <p>Best regards,<br>The Incredible Studios Team</p>
            </div>
            <div class="footer"><p>&copy; 2025 Incredible Studios. All rights reserved.</p></div>
        </div>
    </body>
    </html>
    '''
    msg = Message('Welcome to Incredible Studios!', recipients=[email])
    msg.html = html
    mail.send(msg)

@app.route('/unsubscribe/<email>')
def unsubscribe(email):
    subscriber = Subscriber.query.filter_by(email=email).first()
    if subscriber:
        subscriber.is_active = False
        subscriber.unsubscribed_at = datetime.utcnow()
        db.session.commit()
        flash('You have been unsubscribed from our newsletter.', 'info')
    return redirect(url_for('index'))

@app.route('/unsubscribe', methods=['POST'])
def unsubscribe_post():
    email = request.form.get('email')
    subscriber = Subscriber.query.filter_by(email=email).first()
    if subscriber:
        subscriber.is_active = False
        subscriber.unsubscribed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'message': 'Unsubscribed successfully!'})
    return jsonify({'success': False, 'message': 'Email not found.'})

def track_page_view(page):
    view = PageView(
        page=page,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:300],
        referrer=request.referrer or '',
        session_id=request.cookies.get('session_id', '')
    )
    db.session.add(view)
    db.session.commit()

# ==================== ADMIN NEWSLETTER ROUTES ====================

@app.route('/admin/newsletter')
@login_required
def admin_newsletter():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    subscribers = Subscriber.query.filter_by(is_active=True).order_by(Subscriber.subscribed_at.desc()).all()
    campaigns = NewsletterCampaign.query.order_by(NewsletterCampaign.created_at.desc()).all()
    templates = EmailTemplate.query.all()
    total_subscribers = Subscriber.query.filter_by(is_active=True).count()
    verified_subscribers = Subscriber.query.filter_by(is_verified=True, is_active=True).count()
    
    return render_template('admin/newsletter.html', 
                         subscribers=subscribers,
                         campaigns=campaigns,
                         templates=templates,
                         total_subscribers=total_subscribers,
                         verified_subscribers=verified_subscribers)

@app.route('/admin/newsletter/send', methods=['POST'])
@login_required
def send_newsletter():
    if not check_admin_access():
        return jsonify({'success': False, 'message': 'Access denied'})
    subject = request.form.get('subject')
    content = request.form.get('content')
    send_to = request.form.get('send_to', 'all')
    
    if not subject or not content:
        flash('Subject and content are required!', 'error')
        return redirect(url_for('admin_newsletter'))
    
    if send_to == 'verified':
        subscribers = Subscriber.query.filter_by(is_active=True, is_verified=True).all()
    elif send_to == 'unverified':
        subscribers = Subscriber.query.filter_by(is_active=True, is_verified=False).all()
    else:
        subscribers = Subscriber.query.filter_by(is_active=True).all()
    
    if not subscribers:
        flash('No subscribers found!', 'error')
        return redirect(url_for('admin_newsletter'))
    
    campaign = NewsletterCampaign(
        subject=subject,
        content=content,
        html_content=content,
        status='sent',
        sent_at=datetime.utcnow(),
        total_sent=len(subscribers)
    )
    db.session.add(campaign)
    db.session.commit()
    
    sent_count = 0
    for subscriber in subscribers:
        try:
            send_newsletter_email(subscriber, campaign, subject, content)
            sent_count += 1
        except Exception as e:
            print(f"Failed to send to {subscriber.email}: {e}")
    
    campaign.total_sent = sent_count
    db.session.commit()
    flash(f'Newsletter sent to {sent_count} subscribers!', 'success')
    return redirect(url_for('admin_newsletter'))

def send_newsletter_email(subscriber, campaign, subject, content):
    unsubscribe_url = url_for('unsubscribe', email=subscriber.email, _external=True)
    tracking_pixel = url_for('track_open', campaign_id=campaign.id, subscriber_id=subscriber.id, _external=True)
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #6C63FF; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background: #f9f9f9; }}
        .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #666; }}
        .unsubscribe {{ color: #999; text-decoration: none; }}
    </style></head>
    <body>
        <div class="container">
            <div class="header"><h2>Incredible Studios</h2></div>
            <div class="content">
                <p>Hello {escape(subscriber.name) if subscriber.name else 'there'}!</p>
                {content}
            </div>
            <div class="footer">
                <p><a href="{unsubscribe_url}" class="unsubscribe">Unsubscribe</a></p>
                <p>&copy; 2025 Incredible Studios. All rights reserved.</p>
            </div>
        </div>
        <img src="{tracking_pixel}" width="1" height="1" style="display:none;">
    </body>
    </html>
    '''
    msg = Message(subject, recipients=[subscriber.email])
    msg.html = html
    mail.send(msg)

@app.route('/track/open/<int:campaign_id>/<int:subscriber_id>')
def track_open(campaign_id, subscriber_id):
    existing = EmailTracking.query.filter_by(campaign_id=campaign_id, subscriber_id=subscriber_id).first()
    if not existing:
        tracking = EmailTracking(
            campaign_id=campaign_id,
            subscriber_id=subscriber_id,
            opened_at=datetime.utcnow(),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:300]
        )
        db.session.add(tracking)
        campaign = NewsletterCampaign.query.get(campaign_id)
        if campaign:
            campaign.total_opened = EmailTracking.query.filter_by(campaign_id=campaign_id).count()
        db.session.commit()
    
    from flask import send_file
    import io
    return send_file(
        io.BytesIO(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'),
        mimetype='image/gif'
    )

@app.route('/admin/newsletter/campaign/<int:id>')
@login_required
def view_campaign(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    campaign = NewsletterCampaign.query.get_or_404(id)
    tracking = EmailTracking.query.filter_by(campaign_id=id).all()
    return render_template('admin/campaign_stats.html', campaign=campaign, tracking=tracking)

@app.route('/admin/newsletter/export')
@login_required
def export_subscribers():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    subscribers = Subscriber.query.filter_by(is_active=True).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Email', 'Name', 'Subscribed Date', 'Verified'])
    for sub in subscribers:
        writer.writerow([sub.email, sub.name or '', sub.subscribed_at.strftime('%Y-%m-%d %H:%M:%S'), 'Yes' if sub.is_verified else 'No'])
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=subscribers.csv'
    return response

# ==================== LOGIN MANAGER ====================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== CONTEXT PROCESSOR ====================

@app.context_processor
def inject_settings():
    settings = SiteSettings.query.first()
    if not settings:
        settings = SiteSettings()
        db.session.add(settings)
        db.session.commit()
    return {'settings': settings}

# ==================== FRONTEND ROUTES ====================

@app.route('/')
def index():
    track_page_view('home')
    settings = SiteSettings.query.first()
    featured_projects = Project.query.filter_by(featured=True).limit(6).all()
    services = Service.query.filter_by(active=True).order_by(Service.order).limit(3).all()
    testimonials = Testimonial.query.filter_by(active=True).order_by(Testimonial.order).limit(3).all()
    clients = Client.query.order_by(Client.order).all()
    
    if not clients and settings:
        client_names = json.loads(settings.clients) if settings.clients else []
        clients = [{'name': name} for name in client_names]
    
    return render_template('index.html', 
                         featured_projects=featured_projects,
                         services=services,
                         testimonials=testimonials,
                         clients=clients)

@app.route('/about')
def about():
    track_page_view('about')
    return render_template('about.html')

@app.route('/services')
def services():
    track_page_view('services')
    all_services = Service.query.filter_by(active=True).order_by(Service.order).all()
    return render_template('services.html', services=all_services)

@app.route('/portfolio')
def portfolio():
    track_page_view('portfolio')
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('portfolio.html', projects=projects)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    track_page_view('contact')
    if request.method == 'POST':
        submission = ContactSubmission(
            name=request.form.get('name'),
            email=request.form.get('email'),
            subject=request.form.get('subject'),
            service=request.form.get('service'),
            message=request.form.get('message')
        )
        db.session.add(submission)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Thank you for your message!'})
    return render_template('contact.html')

@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        return json.loads(value)
    return []

# ==================== BLOG FRONTEND ROUTES ====================

@app.route('/blog')
def blog_index():
    track_page_view('blog')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    posts_query = BlogPost.query.filter(
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc())
    
    posts = posts_query.paginate(page=page, per_page=per_page, error_out=False)
    
    categories = db.session.query(
        BlogCategory, func.count(BlogPost.id).label('post_count')
    ).outerjoin(BlogPost, BlogPost.category_id == BlogCategory.id).filter(
        BlogPost.status == 'published'
    ).group_by(BlogCategory.id).all()
    
    tags = BlogTag.query.all()
    recent_posts = BlogPost.query.filter(
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc()).limit(5).all()
    
    return render_template('blog/index.html', 
                         posts=posts,
                         categories=categories,
                         tags=tags,
                         recent_posts=recent_posts)

@app.route('/blog/category/<slug>')
def blog_category(slug):
    track_page_view('blog_category')
    category = BlogCategory.query.filter_by(slug=slug).first_or_404()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    posts = BlogPost.query.filter(
        BlogPost.category_id == category.id,
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    categories = db.session.query(
        BlogCategory, func.count(BlogPost.id).label('post_count')
    ).outerjoin(BlogPost, BlogPost.category_id == BlogCategory.id).filter(
        BlogPost.status == 'published'
    ).group_by(BlogCategory.id).all()
    
    tags = BlogTag.query.all()
    recent_posts = BlogPost.query.filter(
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc()).limit(5).all()
    
    return render_template('blog/index.html',
                         posts=posts,
                         categories=categories,
                         tags=tags,
                         recent_posts=recent_posts,
                         current_category=category)

@app.route('/blog/tag/<slug>')
def blog_tag(slug):
    track_page_view('blog_tag')
    tag = BlogTag.query.filter_by(slug=slug).first_or_404()
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    posts = tag.posts.filter(
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    categories = db.session.query(
        BlogCategory, func.count(BlogPost.id).label('post_count')
    ).outerjoin(BlogPost, BlogPost.category_id == BlogCategory.id).filter(
        BlogPost.status == 'published'
    ).group_by(BlogCategory.id).all()
    
    tags = BlogTag.query.all()
    recent_posts = BlogPost.query.filter(
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc()).limit(5).all()
    
    return render_template('blog/index.html',
                         posts=posts,
                         categories=categories,
                         tags=tags,
                         recent_posts=recent_posts,
                         current_tag=tag)

@app.route('/blog/post/<slug>')
def blog_post(slug):
    track_page_view('blog_post')
    post = BlogPost.query.filter_by(slug=slug).first_or_404()
    
    post.views += 1
    db.session.commit()
    
    comments = BlogComment.query.filter_by(
        post_id=post.id,
        status='approved',
        parent_id=None
    ).order_by(BlogComment.created_at.desc()).all()
    
    related_posts = BlogPost.query.filter(
        BlogPost.category_id == post.category_id,
        BlogPost.id != post.id,
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).limit(3).all()
    
    categories = db.session.query(
        BlogCategory, func.count(BlogPost.id).label('post_count')
    ).outerjoin(BlogPost, BlogPost.category_id == BlogCategory.id).filter(
        BlogPost.status == 'published'
    ).group_by(BlogCategory.id).all()
    
    tags = BlogTag.query.all()
    recent_posts = BlogPost.query.filter(
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc()).limit(5).all()
    
    return render_template('blog/post.html',
                         post=post,
                         comments=comments,
                         related_posts=related_posts,
                         categories=categories,
                         tags=tags,
                         recent_posts=recent_posts)

@app.route('/blog/comment', methods=['POST'])
def add_comment():
    post_id = request.form.get('post_id')
    author_name = request.form.get('author_name')
    author_email = request.form.get('author_email')
    author_website = request.form.get('author_website')
    content = request.form.get('content')
    parent_id = request.form.get('parent_id')
    
    if not all([post_id, author_name, author_email, content]):
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    comment = BlogComment(
        post_id=int(post_id),
        author_name=author_name,
        author_email=author_email,
        author_website=author_website,
        content=content,
        parent_id=int(parent_id) if parent_id else None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:300]
    )
    db.session.add(comment)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Comment submitted for moderation!'})

@app.route('/search')
def search_blog():
    track_page_view('search')
    query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    if query:
        posts = BlogPost.query.filter(
            BlogPost.status == 'published',
            BlogPost.published_at <= datetime.utcnow(),
            (BlogPost.title.contains(query) | BlogPost.content.contains(query) | BlogPost.excerpt.contains(query))
        ).order_by(BlogPost.published_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    else:
        posts = []
    
    categories = db.session.query(
        BlogCategory, func.count(BlogPost.id).label('post_count')
    ).outerjoin(BlogPost, BlogPost.category_id == BlogCategory.id).filter(
        BlogPost.status == 'published'
    ).group_by(BlogCategory.id).all()
    
    tags = BlogTag.query.all()
    recent_posts = BlogPost.query.filter(
        BlogPost.status == 'published',
        BlogPost.published_at <= datetime.utcnow()
    ).order_by(BlogPost.published_at.desc()).limit(5).all()
    
    return render_template('blog/search.html',
                         posts=posts,
                         query=query,
                         categories=categories,
                         tags=tags,
                         recent_posts=recent_posts)

@app.route('/api/projects')
def api_projects():
    projects = Project.query.all()
    return jsonify([{
        'id': p.id,
        'title': p.title,
        'category': p.category,
        'image_url': p.image_url or f'/static/uploads/{p.image_filename}' if p.image_filename else None,
        'client': p.client,
        'year': p.year,
        'services': p.services,
        'description': p.description
    } for p in projects])

# ==================== SEO ROUTES ====================

@app.route('/sitemap.xml')
def sitemap():
    settings = SiteSettings.query.first()
    base_url = request.host_url.rstrip('/')
    
    pages = ['', '/about', '/services', '/portfolio', '/contact', '/blog']
    posts = BlogPost.query.filter_by(status='published').filter(BlogPost.published_at <= datetime.utcnow()).all()
    projects = Project.query.all()
    
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    
    for page in pages:
        xml += f'''  <url>\n    <loc>{base_url}{page}</loc>\n    <lastmod>{datetime.utcnow().strftime('%Y-%m-%d')}</lastmod>\n    <changefreq>{'daily' if page == '/blog' else 'weekly'}</changefreq>\n    <priority>{'1.0' if page == '' else '0.8'}</priority>\n  </url>\n'''
    
    for post in posts:
        xml += f'''  <url>\n    <loc>{base_url}/blog/post/{post.slug}</loc>\n    <lastmod>{post.updated_at.strftime('%Y-%m-%d') if post.updated_at else post.created_at.strftime('%Y-%m-%d')}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.7</priority>\n  </url>\n'''
    
    for project in projects:
        xml += f'''  <url>\n    <loc>{base_url}/portfolio</loc>\n    <lastmod>{project.created_at.strftime('%Y-%m-%d')}</lastmod>\n    <changefreq>monthly</changefreq>\n    <priority>0.6</priority>\n  </url>\n'''
    
    xml += '</urlset>'
    return Response(xml, mimetype='application/xml')

@app.route('/robots.txt')
def robots_txt():
    settings = SiteSettings.query.first()
    robots_content = settings.robots_txt if settings else 'User-agent: *\nAllow: /\n'
    return Response(robots_content, mimetype='text/plain')

# ==================== ADMIN BLOG ROUTES ====================

@app.route('/admin/blog')
@login_required
def admin_blog():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).all()
    return render_template('admin/blog/posts.html', posts=posts)

@app.route('/admin/blog/post/new', methods=['GET', 'POST'])
@login_required
def admin_blog_new():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        title = request.form.get('title')
        slug = request.form.get('slug')
        
        if not slug:
            slug = re.sub(r'[^a-zA-Z0-9-]+', '-', title.lower()).strip('-')
        
        existing = BlogPost.query.filter_by(slug=slug).first()
        if existing:
            slug = f"{slug}-{datetime.utcnow().timestamp()}"
        
        status = request.form.get('status')
        published_at = None
        if status == 'published':
            published_at = datetime.utcnow()
        elif status == 'scheduled':
            scheduled_date = request.form.get('scheduled_date')
            if scheduled_date:
                published_at = datetime.strptime(scheduled_date, '%Y-%m-%d %H:%M')
        
        post = BlogPost(
            title=title,
            slug=slug,
            excerpt=request.form.get('excerpt'),
            content=request.form.get('content'),
            featured_image=request.form.get('featured_image'),
            category_id=int(request.form.get('category_id')) if request.form.get('category_id') else None,
            status=status,
            scheduled_for=published_at if status == 'scheduled' else None,
            published_at=published_at if status == 'published' else None,
            seo_title=request.form.get('seo_title'),
            seo_description=request.form.get('seo_description'),
            seo_keywords=request.form.get('seo_keywords'),
            author_id=current_user.id
        )
        
        db.session.add(post)
        db.session.commit()
        
        tag_names = request.form.get('tags', '').split(',')
        for tag_name in tag_names:
            tag_name = tag_name.strip()
            if tag_name:
                tag_slug = re.sub(r'[^a-zA-Z0-9-]+', '-', tag_name.lower()).strip('-')
                tag = BlogTag.query.filter_by(slug=tag_slug).first()
                if not tag:
                    tag = BlogTag(name=tag_name, slug=tag_slug)
                    db.session.add(tag)
                    db.session.commit()
                post.tags.append(tag)
        
        db.session.commit()
        log_activity(current_user.id, 'Created blog post', f'Created post: {title}')
        flash('Post created successfully!', 'success')
        return redirect(url_for('admin_blog'))
    
    categories = BlogCategory.query.all()
    tags = BlogTag.query.all()
    return render_template('admin/blog/post_form.html', post=None, categories=categories, tags=tags)

@app.route('/admin/blog/post/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def admin_blog_edit(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    post = BlogPost.query.get_or_404(id)
    
    if request.method == 'POST':
        post.title = request.form.get('title')
        new_slug = request.form.get('slug')
        
        if new_slug and new_slug != post.slug:
            existing = BlogPost.query.filter_by(slug=new_slug).first()
            if not existing:
                post.slug = new_slug
        elif not new_slug:
            post.slug = re.sub(r'[^a-zA-Z0-9-]+', '-', post.title.lower()).strip('-')
        
        post.excerpt = request.form.get('excerpt')
        post.content = request.form.get('content')
        post.featured_image = request.form.get('featured_image')
        post.category_id = int(request.form.get('category_id')) if request.form.get('category_id') else None
        post.seo_title = request.form.get('seo_title')
        post.seo_description = request.form.get('seo_description')
        post.seo_keywords = request.form.get('seo_keywords')
        
        new_status = request.form.get('status')
        if new_status != post.status:
            post.status = new_status
            if new_status == 'published':
                post.published_at = datetime.utcnow()
            elif new_status == 'scheduled':
                scheduled_date = request.form.get('scheduled_date')
                if scheduled_date:
                    post.scheduled_for = datetime.strptime(scheduled_date, '%Y-%m-%d %H:%M')
            else:
                post.published_at = None
                post.scheduled_for = None
        
        post.updated_at = datetime.utcnow()
        
        post.tags.clear()
        tag_names = request.form.get('tags', '').split(',')
        for tag_name in tag_names:
            tag_name = tag_name.strip()
            if tag_name:
                tag_slug = re.sub(r'[^a-zA-Z0-9-]+', '-', tag_name.lower()).strip('-')
                tag = BlogTag.query.filter_by(slug=tag_slug).first()
                if not tag:
                    tag = BlogTag(name=tag_name, slug=tag_slug)
                    db.session.add(tag)
                    db.session.commit()
                post.tags.append(tag)
        
        db.session.commit()
        log_activity(current_user.id, 'Edited blog post', f'Edited post: {post.title}')
        flash('Post updated successfully!', 'success')
        return redirect(url_for('admin_blog'))
    
    categories = BlogCategory.query.all()
    tags = BlogTag.query.all()
    tag_string = ', '.join([tag.name for tag in post.tags])
    return render_template('admin/blog/post_form.html', post=post, categories=categories, tags=tags, tag_string=tag_string)

@app.route('/admin/blog/post/delete/<int:id>')
@login_required
def admin_blog_delete(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    post = BlogPost.query.get_or_404(id)
    title = post.title
    db.session.delete(post)
    db.session.commit()
    log_activity(current_user.id, 'Deleted blog post', f'Deleted post: {title}')
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('admin_blog'))

@app.route('/admin/blog/categories')
@login_required
def admin_blog_categories():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    categories = BlogCategory.query.all()
    return render_template('admin/blog/categories.html', categories=categories)

@app.route('/admin/blog/categories/add', methods=['POST'])
@login_required
def admin_blog_category_add():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    name = request.form.get('name')
    slug = re.sub(r'[^a-zA-Z0-9-]+', '-', name.lower()).strip('-')
    
    category = BlogCategory(name=name, slug=slug, description=request.form.get('description'))
    db.session.add(category)
    db.session.commit()
    log_activity(current_user.id, 'Added blog category', f'Added category: {name}')
    flash('Category added successfully!', 'success')
    return redirect(url_for('admin_blog_categories'))

@app.route('/admin/blog/categories/edit/<int:id>', methods=['POST'])
@login_required
def admin_blog_category_edit(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    category = BlogCategory.query.get_or_404(id)
    category.name = request.form.get('name')
    category.slug = re.sub(r'[^a-zA-Z0-9-]+', '-', category.name.lower()).strip('-')
    category.description = request.form.get('description')
    db.session.commit()
    log_activity(current_user.id, 'Edited blog category', f'Edited category: {category.name}')
    flash('Category updated successfully!', 'success')
    return redirect(url_for('admin_blog_categories'))

@app.route('/admin/blog/categories/delete/<int:id>')
@login_required
def admin_blog_category_delete(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    category = BlogCategory.query.get_or_404(id)
    name = category.name
    db.session.delete(category)
    db.session.commit()
    log_activity(current_user.id, 'Deleted blog category', f'Deleted category: {name}')
    flash('Category deleted successfully!', 'success')
    return redirect(url_for('admin_blog_categories'))

@app.route('/admin/blog/comments')
@login_required
def admin_blog_comments():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    comments = BlogComment.query.order_by(BlogComment.created_at.desc()).all()
    return render_template('admin/blog/comments.html', comments=comments)

@app.route('/admin/blog/comments/approve/<int:id>')
@login_required
def admin_blog_comment_approve(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    comment = BlogComment.query.get_or_404(id)
    comment.status = 'approved'
    db.session.commit()
    log_activity(current_user.id, 'Approved comment', f'Approved comment on post {comment.post_id}')
    flash('Comment approved!', 'success')
    return redirect(url_for('admin_blog_comments'))

@app.route('/admin/blog/comments/spam/<int:id>')
@login_required
def admin_blog_comment_spam(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    comment = BlogComment.query.get_or_404(id)
    comment.status = 'spam'
    db.session.commit()
    log_activity(current_user.id, 'Marked comment as spam', f'Marked comment on post {comment.post_id}')
    flash('Comment marked as spam!', 'success')
    return redirect(url_for('admin_blog_comments'))

@app.route('/admin/blog/comments/delete/<int:id>')
@login_required
def admin_blog_comment_delete(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    comment = BlogComment.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    log_activity(current_user.id, 'Deleted comment', f'Deleted comment on post {comment.post_id}')
    flash('Comment deleted!', 'success')
    return redirect(url_for('admin_blog_comments'))

# ==================== ADMIN ROUTES ====================

@app.route('/admin')
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/login.html')

@app.route('/admin/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    
    if IpWhitelist.query.count() > 0:
        ip_allowed = IpWhitelist.query.filter_by(ip_address=request.remote_addr).first()
        if not ip_allowed:
            flash('Access denied from this IP address', 'error')
            return redirect(url_for('admin_login'))
    
    if user and user.is_active and user.check_password(password):
        if user.two_factor_enabled:
            from flask import session
            session['2fa_user_id'] = user.id
            return render_template('admin/2fa_verify.html')
        
        login_user(user)
        user.last_login = datetime.utcnow()
        user.last_ip = request.remote_addr
        db.session.commit()
        log_activity(user.id, 'Logged in', f'Login from {request.remote_addr}', request.remote_addr, request.headers.get('User-Agent', ''))
        return redirect(url_for('admin_dashboard'))
    
    flash('Invalid username or password', 'error')
    return redirect(url_for('admin_login'))

@app.route('/admin/2fa/verify', methods=['POST'])
def verify_2fa_login():
    from flask import session
    user_id = session.get('2fa_user_id')
    if not user_id:
        return redirect(url_for('admin_login'))
    
    user = User.query.get(user_id)
    token = request.form.get('token')
    
    if verify_2fa(user.two_factor_secret, token):
        login_user(user)
        user.last_login = datetime.utcnow()
        user.last_ip = request.remote_addr
        db.session.commit()
        session.pop('2fa_user_id', None)
        log_activity(user.id, 'Logged in with 2FA', f'Login from {request.remote_addr}')
        return redirect(url_for('admin_dashboard'))
    
    flash('Invalid 2FA code', 'error')
    return redirect(url_for('admin_login'))

@app.route('/admin/logout')
@login_required
def logout():
    log_activity(current_user.id, 'Logged out', 'User logged out')
    logout_user()
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    total_views = PageView.query.count()
    total_messages = ContactSubmission.query.count()
    unread_messages = ContactSubmission.query.filter_by(is_read=False).count()
    total_projects = Project.query.count()
    featured_projects = Project.query.filter_by(featured=True).count()
    total_services = Service.query.count()
    active_services = Service.query.filter_by(active=True).count()
    total_testimonials = Testimonial.query.count()
    active_testimonials = Testimonial.query.filter_by(active=True).count()
    total_clients = Client.query.count()
    
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_views = PageView.query.filter(PageView.created_at >= thirty_days_ago).count()
    
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_views = PageView.query.filter(PageView.created_at >= today_start).count()
    
    week_ago = datetime.utcnow() - timedelta(days=7)
    weekly_views = PageView.query.filter(PageView.created_at >= week_ago).count()
    
    weekly_activity = []
    weekly_max = 0
    for i in range(6, -1, -1):
        day_date = datetime.utcnow() - timedelta(days=i)
        day_start = day_date.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count = PageView.query.filter(PageView.created_at >= day_start, PageView.created_at < day_end).count()
        day_name = day_date.strftime('%A')[:3]
        weekly_activity.append({'day': day_name, 'count': count})
        if count > weekly_max:
            weekly_max = count
    
    page_stats = db.session.query(PageView.page, func.count(PageView.id)).group_by(PageView.page).all()
    recent_messages = ContactSubmission.query.order_by(ContactSubmission.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_views=total_views,
                         total_messages=total_messages,
                         unread_messages=unread_messages,
                         total_projects=total_projects,
                         featured_projects=featured_projects,
                         total_services=total_services,
                         active_services=active_services,
                         total_testimonials=total_testimonials,
                         active_testimonials=active_testimonials,
                         total_clients=total_clients,
                         recent_views=recent_views,
                         today_views=today_views,
                         weekly_views=weekly_views,
                         weekly_activity=weekly_activity,
                         weekly_max=weekly_max,
                         page_stats=page_stats,
                         recent_messages=recent_messages,
                         now=datetime.utcnow())

# ==================== ANALYTICS ROUTES ====================

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/analytics.html')

@app.route('/admin/analytics/data')
@login_required
def analytics_data():
    if not check_admin_access():
        return jsonify({'error': 'Access denied'}), 403
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
    else:
        start_date = datetime.utcnow() - timedelta(days=30)
    
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    else:
        end_date = datetime.utcnow()
    
    views_over_time = db.session.query(
        func.date(PageView.created_at).label('date'),
        func.count(PageView.id).label('count')
    ).filter(
        PageView.created_at >= start_date,
        PageView.created_at <= end_date
    ).group_by(func.date(PageView.created_at)).all()
    
    all_views = PageView.query.filter(PageView.created_at >= start_date, PageView.created_at <= end_date).all()
    device_stats = {}
    browser_stats = {}
    os_stats = {}
    
    for view in all_views:
        device = get_device_type(view.user_agent)
        browser = get_browser_name(view.user_agent)
        os_name = get_os_name(view.user_agent)
        
        device_stats[device] = device_stats.get(device, 0) + 1
        browser_stats[browser] = browser_stats.get(browser, 0) + 1
        os_stats[os_name] = os_stats.get(os_name, 0) + 1
    
    page_stats = db.session.query(
        PageView.page, func.count(PageView.id)
    ).filter(
        PageView.created_at >= start_date,
        PageView.created_at <= end_date
    ).group_by(PageView.page).all()
    
    unique_ips = db.session.query(PageView.ip_address).filter(
        PageView.created_at >= start_date,
        PageView.created_at <= end_date
    ).distinct().count()
    
    total_views_count = len(all_views)
    
    form_submissions = ContactSubmission.query.filter(
        ContactSubmission.created_at >= start_date,
        ContactSubmission.created_at <= end_date
    ).count()
    
    conversion_rate = (form_submissions / total_views_count * 100) if total_views_count > 0 else 0
    
    return jsonify({
        'views_over_time': [{'date': str(v.date), 'count': v.count} for v in views_over_time],
        'device_stats': [{'name': k, 'value': v} for k, v in device_stats.items()],
        'browser_stats': [{'name': k, 'value': v} for k, v in browser_stats.items()],
        'os_stats': [{'name': k, 'value': v} for k, v in os_stats.items()],
        'page_stats': [{'page': p[0] or 'Home', 'views': p[1]} for p in page_stats],
        'unique_visitors': unique_ips,
        'total_views': total_views_count,
        'form_submissions': form_submissions,
        'conversion_rate': round(conversion_rate, 2),
        'bounce_rate': 0
    })

@app.route('/admin/analytics/export')
@login_required
def export_analytics():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    
    format_type = request.args.get('format', 'csv')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
    else:
        start_date = datetime.utcnow() - timedelta(days=30)
    
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
    else:
        end_date = datetime.utcnow()
    
    views = PageView.query.filter(
        PageView.created_at >= start_date,
        PageView.created_at <= end_date
    ).order_by(PageView.created_at.desc()).all()
    
    if format_type == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Page', 'IP Address', 'User Agent', 'Referrer'])
        for view in views:
            writer.writerow([view.created_at.strftime('%Y-%m-%d %H:%M:%S'), view.page, view.ip_address, view.user_agent[:100], view.referrer or ''])
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = f'attachment; filename=analytics_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.csv'
        return response
    
    return jsonify({'error': 'Invalid format'}), 400

# ==================== USER MANAGEMENT ROUTES ====================

@app.route('/admin/users')
@login_required
def admin_users():
    if not check_super_admin():
        flash('Access denied. Super admin only.', 'error')
        return redirect(url_for('admin_dashboard'))
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
    if not check_super_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('admin_users'))
    
    user = User(username=username, email=email, role=role, is_active=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    log_activity(current_user.id, 'Added user', f'Added user: {username}')
    flash('User added successfully', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/edit/<int:id>', methods=['POST'])
@login_required
def edit_user(id):
    if not check_super_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    user = User.query.get_or_404(id)
    user.role = request.form.get('role')
    user.is_active = 'is_active' in request.form
    
    if request.form.get('password'):
        user.set_password(request.form.get('password'))
    
    db.session.commit()
    log_activity(current_user.id, 'Edited user', f'Edited user: {user.username}')
    flash('User updated successfully', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:id>')
@login_required
def delete_user(id):
    if not check_super_admin():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    log_activity(current_user.id, 'Deleted user', f'Deleted user: {user.username}')
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if request.method == 'POST':
        current_user.email = request.form.get('email')
        if request.form.get('password'):
            current_user.set_password(request.form.get('password'))
        
        if 'enable_2fa' in request.form:
            current_user.two_factor_enabled = True
            if not current_user.two_factor_secret:
                current_user.two_factor_secret = generate_2fa_secret()
        else:
            current_user.two_factor_enabled = False
        
        db.session.commit()
        log_activity(current_user.id, 'Updated profile', 'Profile updated')
        flash('Profile updated successfully', 'success')
        return redirect(url_for('admin_profile'))
    
    qr_code = None
    if not current_user.two_factor_secret:
        current_user.two_factor_secret = generate_2fa_secret()
        db.session.commit()
    
    if current_user.two_factor_secret and not current_user.two_factor_enabled:
        qr_code = get_2fa_qr_code(current_user.two_factor_secret, current_user.username)
    
    return render_template('admin/profile.html', user=current_user, qr_code=qr_code)

@app.route('/admin/verify-2fa', methods=['POST'])
@login_required
def verify_2fa_setup():
    token = request.form.get('token')
    if verify_2fa(current_user.two_factor_secret, token):
        current_user.two_factor_enabled = True
        db.session.commit()
        flash('2FA enabled successfully!', 'success')
    else:
        flash('Invalid 2FA code. Please try again.', 'error')
    return redirect(url_for('admin_profile'))

@app.route('/admin/activity-logs')
@login_required
def admin_activity_logs():
    if not check_super_admin():
        flash('Access denied. Super admin only.', 'error')
        return redirect(url_for('admin_dashboard'))
    logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(200).all()
    return render_template('admin/activity_logs.html', logs=logs)

@app.route('/admin/ip-whitelist')
@login_required
def admin_ip_whitelist():
    if not check_super_admin():
        flash('Access denied. Super admin only.', 'error')
        return redirect(url_for('admin_dashboard'))
    ips = IpWhitelist.query.all()
    return render_template('admin/ip_whitelist.html', ips=ips)

@app.route('/admin/ip-whitelist/add', methods=['POST'])
@login_required
def add_ip_whitelist():
    if not check_super_admin():
        return jsonify({'success': False, 'message': 'Access denied'})
    
    ip = IpWhitelist(ip_address=request.form.get('ip_address'), description=request.form.get('description'))
    db.session.add(ip)
    db.session.commit()
    log_activity(current_user.id, 'Added IP to whitelist', f'Added IP: {request.form.get("ip_address")}')
    flash('IP added to whitelist', 'success')
    return redirect(url_for('admin_ip_whitelist'))

@app.route('/admin/ip-whitelist/delete/<int:id>')
@login_required
def delete_ip_whitelist(id):
    if not check_super_admin():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    
    ip = IpWhitelist.query.get_or_404(id)
    db.session.delete(ip)
    db.session.commit()
    log_activity(current_user.id, 'Removed IP from whitelist', f'Removed IP: {ip.ip_address}')
    flash('IP removed from whitelist', 'success')
    return redirect(url_for('admin_ip_whitelist'))

# ==================== SEO SETTINGS ROUTES ====================

@app.route('/admin/seo')
@login_required
def admin_seo():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    settings = SiteSettings.query.first()
    return render_template('admin/seo.html', settings=settings)

@app.route('/admin/seo/update', methods=['POST'])
@login_required
def update_seo():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    
    settings = SiteSettings.query.first()
    if not settings:
        settings = SiteSettings()
        db.session.add(settings)
    
    settings.google_analytics_id = request.form.get('google_analytics_id')
    settings.meta_description = request.form.get('meta_description')
    settings.meta_keywords = request.form.get('meta_keywords')
    settings.meta_author = request.form.get('meta_author')
    settings.robots_txt = request.form.get('robots_txt')
    
    db.session.commit()
    log_activity(current_user.id, 'Updated SEO settings', 'SEO settings updated')
    flash('SEO settings updated successfully!', 'success')
    return redirect(url_for('admin_seo'))

# ==================== ADMIN SETTINGS ROUTES ====================

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    settings = SiteSettings.query.first()
    if not settings:
        settings = SiteSettings()
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        settings.site_name = request.form.get('site_name')
        settings.site_tagline = request.form.get('site_tagline')
        settings.logo_text = request.form.get('logo_text')
        settings.studio_text = request.form.get('studio_text')
        settings.since_year = request.form.get('since_year')
        settings.primary_color = request.form.get('primary_color')
        settings.secondary_color = request.form.get('secondary_color')
        settings.footer_text = request.form.get('footer_text')
        settings.hero_title_prefix = request.form.get('hero_title_prefix')
        settings.hero_title_highlight = request.form.get('hero_title_highlight')
        settings.hero_description = request.form.get('hero_description')
        settings.hero_button_text = request.form.get('hero_button_text')
        settings.hero_button2_text = request.form.get('hero_button2_text')
        settings.hero_badge_text = request.form.get('hero_badge_text')
        settings.clients_title = request.form.get('clients_title')
        settings.services_badge = request.form.get('services_badge')
        settings.services_title = request.form.get('services_title')
        settings.services_subtitle = request.form.get('services_subtitle')
        settings.portfolio_badge = request.form.get('portfolio_badge')
        settings.portfolio_title = request.form.get('portfolio_title')
        settings.portfolio_subtitle = request.form.get('portfolio_subtitle')
        settings.testimonials_badge = request.form.get('testimonials_badge')
        settings.testimonials_title = request.form.get('testimonials_title')
        settings.testimonials_subtitle = request.form.get('testimonials_subtitle')
        settings.cta_title = request.form.get('cta_title')
        settings.cta_description = request.form.get('cta_description')
        settings.cta_button_text = request.form.get('cta_button_text')
        settings.cta_button2_text = request.form.get('cta_button2_text')
        settings.footer_copyright = request.form.get('footer_copyright')
        settings.contact_email = request.form.get('contact_email')
        settings.contact_phone = request.form.get('contact_phone')
        settings.contact_address = request.form.get('contact_address')
        settings.contact_hours = request.form.get('contact_hours')
        settings.about_title = request.form.get('about_title')
        settings.about_description = request.form.get('about_description')
        settings.about_description2 = request.form.get('about_description2')
        settings.projects_count = request.form.get('projects_count')
        settings.projects_label = request.form.get('projects_label')
        settings.clients_count = request.form.get('clients_count')
        settings.clients_label = request.form.get('clients_label')
        
        client_names = request.form.get('clients_list', '').split(',')
        client_names = [c.strip() for c in client_names if c.strip()]
        settings.clients = json.dumps(client_names)
        
        if 'hero_image' in request.files and request.files['hero_image'].filename:
            file = request.files['hero_image']
            filename = secure_filename(f"hero_{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            settings.hero_image = f'/static/uploads/{filename}'
        elif request.form.get('hero_image_url'):
            settings.hero_image = request.form.get('hero_image_url')
        
        if 'about_image' in request.files and request.files['about_image'].filename:
            file = request.files['about_image']
            filename = secure_filename(f"about_{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            settings.about_image = f'/static/uploads/{filename}'
        elif request.form.get('about_image_url'):
            settings.about_image = request.form.get('about_image_url')
        
        db.session.commit()
        log_activity(current_user.id, 'Updated site settings', 'Site settings updated')
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('admin_settings'))
    
    clients_list = json.loads(settings.clients) if settings.clients else ['Brand 1', 'Brand 2', 'Brand 3', 'Brand 4', 'Brand 5']
    return render_template('admin/settings.html', settings=settings, clients_list=clients_list)

# ==================== ADMIN SERVICE ROUTES ====================

@app.route('/admin/services', methods=['GET', 'POST'])
@login_required
def admin_services():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        service = Service(
            title=request.form.get('title'),
            description=request.form.get('description'),
            icon_name=request.form.get('icon_name'),
            features=json.dumps(request.form.getlist('features')),
            order=int(request.form.get('order', 0)),
            active='active' in request.form
        )
        db.session.add(service)
        db.session.commit()
        log_activity(current_user.id, 'Added service', f'Added service: {request.form.get("title")}')
        flash('Service added successfully!', 'success')
        return redirect(url_for('admin_services'))
    
    services = Service.query.order_by(Service.order).all()
    return render_template('admin/services.html', services=services)

@app.route('/admin/services/edit/<int:id>', methods=['POST'])
@login_required
def edit_service(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    service = Service.query.get_or_404(id)
    service.title = request.form.get('title')
    service.description = request.form.get('description')
    service.icon_name = request.form.get('icon_name')
    service.features = json.dumps(request.form.getlist('features'))
    service.order = int(request.form.get('order', 0))
    service.active = 'active' in request.form
    db.session.commit()
    log_activity(current_user.id, 'Edited service', f'Edited service: {service.title}')
    flash('Service updated successfully!', 'success')
    return redirect(url_for('admin_services'))

@app.route('/admin/services/delete/<int:id>')
@login_required
def delete_service(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    service = Service.query.get_or_404(id)
    title = service.title
    db.session.delete(service)
    db.session.commit()
    log_activity(current_user.id, 'Deleted service', f'Deleted service: {title}')
    flash('Service deleted successfully!', 'success')
    return redirect(url_for('admin_services'))

# ==================== ADMIN TESTIMONIAL ROUTES ====================

@app.route('/admin/testimonials', methods=['GET', 'POST'])
@login_required
def admin_testimonials():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        testimonial = Testimonial(
            name=request.form.get('name'),
            position=request.form.get('position'),
            company=request.form.get('company'),
            content=request.form.get('content'),
            rating=int(request.form.get('rating', 5)),
            order=int(request.form.get('order', 0)),
            active='active' in request.form
        )
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            filename = secure_filename(f"testimonial_{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            testimonial.image_url = f'/static/uploads/{filename}'
        elif request.form.get('image_url'):
            testimonial.image_url = request.form.get('image_url')
        
        db.session.add(testimonial)
        db.session.commit()
        log_activity(current_user.id, 'Added testimonial', f'Added testimonial from {request.form.get("name")}')
        flash('Testimonial added successfully!', 'success')
        return redirect(url_for('admin_testimonials'))
    
    testimonials = Testimonial.query.order_by(Testimonial.order).all()
    return render_template('admin/testimonials.html', testimonials=testimonials)

@app.route('/admin/testimonials/edit/<int:id>', methods=['POST'])
@login_required
def edit_testimonial(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    testimonial = Testimonial.query.get_or_404(id)
    testimonial.name = request.form.get('name')
    testimonial.position = request.form.get('position')
    testimonial.company = request.form.get('company')
    testimonial.content = request.form.get('content')
    testimonial.rating = int(request.form.get('rating', 5))
    testimonial.order = int(request.form.get('order', 0))
    testimonial.active = 'active' in request.form
    
    if 'image' in request.files and request.files['image'].filename:
        file = request.files['image']
        filename = secure_filename(f"testimonial_{datetime.now().timestamp()}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        testimonial.image_url = f'/static/uploads/{filename}'
    elif request.form.get('image_url'):
        testimonial.image_url = request.form.get('image_url')
    
    db.session.commit()
    log_activity(current_user.id, 'Edited testimonial', f'Edited testimonial from {testimonial.name}')
    flash('Testimonial updated successfully!', 'success')
    return redirect(url_for('admin_testimonials'))

@app.route('/admin/testimonials/delete/<int:id>')
@login_required
def delete_testimonial(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    testimonial = Testimonial.query.get_or_404(id)
    name = testimonial.name
    db.session.delete(testimonial)
    db.session.commit()
    log_activity(current_user.id, 'Deleted testimonial', f'Deleted testimonial from {name}')
    flash('Testimonial deleted successfully!', 'success')
    return redirect(url_for('admin_testimonials'))

# ==================== ADMIN CLIENT ROUTES ====================

@app.route('/admin/clients', methods=['GET', 'POST'])
@login_required
def admin_clients():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        client = Client(
            name=request.form.get('name'),
            website=request.form.get('website'),
            order=int(request.form.get('order', 0))
        )
        if 'logo' in request.files and request.files['logo'].filename:
            file = request.files['logo']
            filename = secure_filename(f"client_{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            client.logo_url = f'/static/uploads/{filename}'
        elif request.form.get('logo_url'):
            client.logo_url = request.form.get('logo_url')
        
        db.session.add(client)
        db.session.commit()
        log_activity(current_user.id, 'Added client', f'Added client: {request.form.get("name")}')
        flash('Client added successfully!', 'success')
        return redirect(url_for('admin_clients'))
    
    clients = Client.query.order_by(Client.order).all()
    return render_template('admin/clients.html', clients=clients)

@app.route('/admin/clients/edit/<int:id>', methods=['POST'])
@login_required
def edit_client(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    client = Client.query.get_or_404(id)
    client.name = request.form.get('name')
    client.website = request.form.get('website')
    client.order = int(request.form.get('order', 0))
    
    if 'logo' in request.files and request.files['logo'].filename:
        file = request.files['logo']
        filename = secure_filename(f"client_{datetime.now().timestamp()}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        client.logo_url = f'/static/uploads/{filename}'
    elif request.form.get('logo_url'):
        client.logo_url = request.form.get('logo_url')
    
    db.session.commit()
    log_activity(current_user.id, 'Edited client', f'Edited client: {client.name}')
    flash('Client updated successfully!', 'success')
    return redirect(url_for('admin_clients'))

@app.route('/admin/clients/delete/<int:id>')
@login_required
def delete_client(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    client = Client.query.get_or_404(id)
    name = client.name
    db.session.delete(client)
    db.session.commit()
    log_activity(current_user.id, 'Deleted client', f'Deleted client: {name}')
    flash('Client deleted successfully!', 'success')
    return redirect(url_for('admin_clients'))

# ==================== ADMIN PROJECT ROUTES ====================

@app.route('/admin/projects')
@login_required
def admin_projects():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('admin/projects.html', projects=projects)

@app.route('/admin/projects/add', methods=['GET', 'POST'])
@login_required
def add_project():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        project = Project(
            title=request.form.get('title'),
            category=request.form.get('category'),
            client=request.form.get('client'),
            year=request.form.get('year'),
            services=request.form.get('services'),
            description=request.form.get('description'),
            challenge=request.form.get('challenge'),
            approach=request.form.get('approach'),
            results=request.form.get('results'),
            featured='featured' in request.form
        )
        
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            filename = secure_filename(f"project_{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            project.image_filename = filename
        elif request.form.get('image_url'):
            project.image_url = request.form.get('image_url')
        
        db.session.add(project)
        db.session.commit()
        log_activity(current_user.id, 'Added project', f'Added project: {request.form.get("title")}')
        flash('Project added successfully!', 'success')
        return redirect(url_for('admin_projects'))
    
    return render_template('admin/add_project.html')

@app.route('/admin/projects/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_project(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    project = Project.query.get_or_404(id)
    
    if request.method == 'POST':
        project.title = request.form.get('title')
        project.category = request.form.get('category')
        project.client = request.form.get('client')
        project.year = request.form.get('year')
        project.services = request.form.get('services')
        project.description = request.form.get('description')
        project.challenge = request.form.get('challenge')
        project.approach = request.form.get('approach')
        project.results = request.form.get('results')
        project.featured = 'featured' in request.form
        
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            filename = secure_filename(f"project_{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            project.image_filename = filename
            project.image_url = None
        elif request.form.get('image_url'):
            project.image_url = request.form.get('image_url')
            project.image_filename = None
        
        db.session.commit()
        log_activity(current_user.id, 'Edited project', f'Edited project: {project.title}')
        flash('Project updated successfully!', 'success')
        return redirect(url_for('admin_projects'))
    
    return render_template('admin/edit_project.html', project=project)

@app.route('/admin/projects/delete/<int:id>')
@login_required
def delete_project(id):
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    project = Project.query.get_or_404(id)
    title = project.title
    db.session.delete(project)
    db.session.commit()
    log_activity(current_user.id, 'Deleted project', f'Deleted project: {title}')
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('admin_projects'))

# ==================== ADMIN MESSAGE ROUTES ====================

@app.route('/admin/messages')
@login_required
def admin_messages():
    if not check_admin_access():
        flash('Access denied', 'error')
        return redirect(url_for('admin_dashboard'))
    messages = ContactSubmission.query.order_by(ContactSubmission.created_at.desc()).all()
    return render_template('admin/messages.html', messages=messages)

@app.route('/admin/messages/mark-read/<int:id>')
@login_required
def mark_message_read(id):
    if not check_admin_access():
        return jsonify({'success': False, 'message': 'Access denied'})
    message = ContactSubmission.query.get_or_404(id)
    message.is_read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/messages/delete/<int:id>')
@login_required
def delete_message(id):
    if not check_admin_access():
        return jsonify({'success': False, 'message': 'Access denied'})
    message = ContactSubmission.query.get_or_404(id)
    db.session.delete(message)
    db.session.commit()
    return jsonify({'success': True})

# ==================== RUN APP ====================

if __name__ == '__main__':
    app.run(debug=True)