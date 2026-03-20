from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, Response, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from sqlalchemy import text, func, desc
from urllib.parse import quote_plus
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler
import re
import smtplib
import socket
import hmac
import json
from email.message import EmailMessage
import base64
import hashlib
import secrets
from uuid import uuid4
from datetime import datetime, timedelta, date
import os
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import (
    db,
    Product,
    Order,
    User,
    SystemSetting,
    AlertLog,
    LowStockAlertState,
    Sale,
    ProductView,
    PasswordResetToken,
    AuditLog,
    MarketRequest,
    RequestResponse,
)

from cryptography.fernet import Fernet, InvalidToken

try:
    from PIL import Image, ImageOps
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'autoseller.db')
load_dotenv(os.path.join(BASE_DIR, '.env'))

database_url = os.getenv('DATABASE_URL', f"sqlite:///{DB_PATH}")
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'replace-this-with-a-secure-key')
if app.secret_key == 'replace-this-with-a-secure-key':
    app.logger.warning('FLASK_SECRET_KEY is using the default value. Set FLASK_SECRET_KEY in environment for production.')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['PRODUCT_UPLOAD_DIR'] = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = app.config['PRODUCT_UPLOAD_DIR']
app.config['PRODUCT_IMAGE_MAX_SIDE'] = 1400
app.config['PRODUCT_IMAGE_JPEG_QUALITY'] = 82
os.makedirs(app.config['PRODUCT_UPLOAD_DIR'], exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}

# Low-stock alert delivery config via environment variables
app.config['SMTP_HOST'] = os.getenv('SMTP_HOST', '')
app.config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', '587'))
app.config['SMTP_USERNAME'] = os.getenv('SMTP_USERNAME', '')
app.config['SMTP_PASSWORD'] = os.getenv('SMTP_PASSWORD', '')
app.config['SMTP_USE_TLS'] = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
app.config['ALERT_EMAIL_FROM'] = os.getenv('ALERT_EMAIL_FROM', app.config['SMTP_USERNAME'])
app.config['ALERT_EMAIL_TO'] = os.getenv('ALERT_EMAIL_TO', '')

app.config['TWILIO_ACCOUNT_SID'] = os.getenv('TWILIO_ACCOUNT_SID', '')
app.config['TWILIO_AUTH_TOKEN'] = os.getenv('TWILIO_AUTH_TOKEN', '')
app.config['TWILIO_WHATSAPP_FROM'] = os.getenv('TWILIO_WHATSAPP_FROM', '')
app.config['ALERT_WHATSAPP_TO'] = os.getenv('ALERT_WHATSAPP_TO', '')
app.config['ALERT_EMAIL_ENABLED'] = os.getenv('ALERT_EMAIL_ENABLED', 'true').lower() == 'true'
app.config['ALERT_WHATSAPP_ENABLED'] = os.getenv('ALERT_WHATSAPP_ENABLED', 'true').lower() == 'true'
app.config['ALERT_MIN_INTERVAL_MINUTES'] = int(os.getenv('ALERT_MIN_INTERVAL_MINUTES', '240'))
app.config['ALERT_ESCALATION_DROP_STEP'] = int(os.getenv('ALERT_ESCALATION_DROP_STEP', '2'))
app.config['SELF_SIGNUP_REQUIRE_APPROVAL'] = os.getenv('SELF_SIGNUP_REQUIRE_APPROVAL', 'false').lower() == 'true'
app.config['PAYSTACK_PUBLIC_KEY'] = os.getenv('PAYSTACK_PUBLIC_KEY', '')
app.config['PAYSTACK_SECRET_KEY'] = os.getenv('PAYSTACK_SECRET_KEY', '')

ALERT_SETTING_KEYS = [
    'SMTP_HOST',
    'SMTP_PORT',
    'SMTP_USERNAME',
    'SMTP_PASSWORD',
    'SMTP_USE_TLS',
    'ALERT_EMAIL_FROM',
    'ALERT_EMAIL_TO',
    'TWILIO_ACCOUNT_SID',
    'TWILIO_AUTH_TOKEN',
    'TWILIO_WHATSAPP_FROM',
    'ALERT_WHATSAPP_TO',
    'ALERT_EMAIL_ENABLED',
    'ALERT_WHATSAPP_ENABLED',
    'ALERT_MIN_INTERVAL_MINUTES',
    'ALERT_ESCALATION_DROP_STEP',
    'PAYSTACK_PUBLIC_KEY',
    'PAYSTACK_SECRET_KEY',
]

SENSITIVE_SETTING_KEYS = {
    'SMTP_PASSWORD',
    'TWILIO_AUTH_TOKEN',
    'PAYSTACK_SECRET_KEY',
}

# Initialize SQLAlchemy and migrations
db.init_app(app)
migrate = Migrate(app, db)


def slugify_text(value):
    base = re.sub(r'[^a-z0-9]+', '-', (value or '').strip().lower()).strip('-')
    return base or 'store'


def generate_unique_store_slug(base_value, exclude_user_id=None):
    base_slug = slugify_text(base_value)
    candidate = base_slug
    counter = 2

    while True:
        query = User.query.filter_by(store_slug=candidate)
        if exclude_user_id is not None:
            query = query.filter(User.id != exclude_user_id)
        if not query.first():
            return candidate
        candidate = f'{base_slug}-{counter}'
        counter += 1

with app.app_context():
    db.create_all()

    # Override environment defaults with persisted admin-managed settings.
    persisted_settings = SystemSetting.query.filter(SystemSetting.key.in_(ALERT_SETTING_KEYS)).all()
    for setting in persisted_settings:
        if setting.key in SENSITIVE_SETTING_KEYS:
            app.config[setting.key] = setting.value or ''
        elif setting.key in ('SMTP_PORT', 'ALERT_MIN_INTERVAL_MINUTES', 'ALERT_ESCALATION_DROP_STEP'):
            defaults = {
                'SMTP_PORT': 587,
                'ALERT_MIN_INTERVAL_MINUTES': 240,
                'ALERT_ESCALATION_DROP_STEP': 2,
            }
            try:
                app.config[setting.key] = int(setting.value or str(defaults[setting.key]))
            except ValueError:
                app.config[setting.key] = defaults.get(setting.key, 0)
        elif setting.key in ('SMTP_USE_TLS', 'ALERT_EMAIL_ENABLED', 'ALERT_WHATSAPP_ENABLED'):
            app.config[setting.key] = str(setting.value or 'true').lower() == 'true'
        else:
            app.config[setting.key] = setting.value or ''

    is_sqlite = db.engine.dialect.name == 'sqlite'
    user_columns = [column.name for column in User.__table__.columns]

    # Legacy bootstrap migrations are SQLite-specific and should not run on PostgreSQL.
    if is_sqlite:
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(product)"))
            columns = [row[1] for row in result.fetchall()]
            if 'low_stock_threshold' not in columns:
                conn.execute(text("ALTER TABLE product ADD COLUMN low_stock_threshold INTEGER DEFAULT 3"))
            if 'image_url' not in columns:
                conn.execute(text("ALTER TABLE product ADD COLUMN image_url VARCHAR(300)"))
            if 'seller_id' not in columns:
                conn.execute(text("ALTER TABLE product ADD COLUMN seller_id INTEGER"))
            if 'is_active' not in columns:
                conn.execute(text("ALTER TABLE product ADD COLUMN is_active BOOLEAN DEFAULT 1"))
            if 'category' not in columns:
                conn.execute(text("ALTER TABLE product ADD COLUMN category VARCHAR(80)"))

    fallback_seller_id = db.session.execute(text("SELECT id FROM user ORDER BY id ASC LIMIT 1")).scalar()
    if fallback_seller_id is not None:
        db.session.execute(
            text("UPDATE product SET seller_id = :seller_id WHERE seller_id IS NULL"),
            {'seller_id': fallback_seller_id}
        )
        db.session.execute(text("UPDATE product SET is_active = 1 WHERE is_active IS NULL"))
        db.session.commit()

    # Keep order table compatible with public storefront order capture fields.
    if is_sqlite:
        with db.engine.connect() as conn:
            order_columns = [row[1] for row in conn.execute(text("PRAGMA table_info('order')")).fetchall()]
            if 'customer_address' not in order_columns:
                conn.execute(text("ALTER TABLE 'order' ADD COLUMN customer_address VARCHAR(255)"))
            if 'payment_status' not in order_columns:
                conn.execute(text("ALTER TABLE 'order' ADD COLUMN payment_status VARCHAR(20) DEFAULT 'pending'"))
            if 'payment_reference' not in order_columns:
                conn.execute(text("ALTER TABLE 'order' ADD COLUMN payment_reference VARCHAR(120)"))

    db.session.execute(text("UPDATE 'order' SET payment_status = 'pending' WHERE payment_status IS NULL OR payment_status = ''"))
    db.session.commit()

    # If user table schema changed with password_hash, migrate existing data if needed.
    if is_sqlite:
        with db.engine.connect() as conn:
            user_columns = [row[1] for row in conn.execute(text("PRAGMA table_info(user)")).fetchall()]

        if 'password_hash' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN password_hash VARCHAR(128)"))

        if 'role' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'admin'"))

        if 'email' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN email VARCHAR(120)"))

        if 'store_slug' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN store_slug VARCHAR(80)"))

        if 'store_name' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN store_name VARCHAR(120)"))

        if 'store_description' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN store_description TEXT"))

        if 'is_approved' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN is_approved BOOLEAN DEFAULT 1"))

        if 'store_logo' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN store_logo VARCHAR(300)"))

        if 'store_whatsapp' not in user_columns:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN store_whatsapp VARCHAR(30)"))

    user_columns = [column.name for column in User.__table__.columns]

    db.session.execute(text("UPDATE user SET role = 'admin' WHERE role IS NULL OR role = ''"))
    db.session.execute(text("UPDATE user SET is_approved = 1 WHERE is_approved IS NULL"))
    db.session.commit()

    users_missing_slugs = User.query.filter((User.store_slug.is_(None)) | (User.store_slug == '')).all()
    for user in users_missing_slugs:
        user.store_slug = generate_unique_store_slug(user.username, exclude_user_id=user.id)
        if not user.store_name:
            user.store_name = user.username
    db.session.commit()

    # Migrate plain password values into password_hash if source column exists
    if 'password' in user_columns:
        result = db.session.execute(text("SELECT id, password, password_hash FROM user")).fetchall()
        for user_id, raw_password, existing_hash in result:
            user_obj = db.session.get(User, user_id)
            if not user_obj:
                continue

            if not raw_password:
                continue

            password_text = str(raw_password)
            if existing_hash:
                # Legacy column might still hold cleartext from old builds; sync to hash.
                user_obj.password = existing_hash
                continue

            if password_text.startswith('scrypt:') or password_text.startswith('pbkdf2:'):
                user_obj.password_hash = password_text
                user_obj.password = password_text
            else:
                user_obj.set_password(password_text)
        db.session.commit()

    # Add default admin user for first-time setup
    default_admin_username = (os.getenv('DEFAULT_ADMIN_USERNAME', 'admin') or 'admin').strip()
    default_admin_email = (os.getenv('DEFAULT_ADMIN_EMAIL', 'admin@example.com') or '').strip() or None
    default_admin_password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin123')

    if default_admin_password == 'admin123':
        app.logger.warning('DEFAULT_ADMIN_PASSWORD is using the default value. Set a strong value in production.')

    admin_user = User.query.filter_by(username=default_admin_username).first()
    if not admin_user and default_admin_username != 'admin':
        admin_user = User.query.filter_by(username='admin').first()

    if not admin_user:
        admin_user = User(
            username=default_admin_username,
            email=default_admin_email,
            role='admin',
            store_slug=generate_unique_store_slug(default_admin_username),
            store_name='Admin Store',
            is_approved=True,
        )
        admin_user.set_password(default_admin_password)
        db.session.add(admin_user)
        db.session.commit()
    elif admin_user and not admin_user.password_hash:
        admin_user.set_password(default_admin_password)
        db.session.commit()

    if not admin_user.email and default_admin_email:
        admin_user.email = default_admin_email
        db.session.commit()

    if getattr(admin_user, 'is_approved', None) is not True:
        admin_user.is_approved = True
        db.session.commit()
    if not admin_user.store_slug:
        admin_user.store_slug = generate_unique_store_slug(admin_user.username, exclude_user_id=admin_user.id)
    if not admin_user.store_name:
        admin_user.store_name = admin_user.username
    db.session.commit()

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

app.jinja_env.globals['quote_plus'] = quote_plus


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def role_required(*roles):
    """Protect routes to one or more roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def owns_product(product):
    return current_user.role == 'admin' or product.seller_id == current_user.id


def owns_order(order):
    product = order.product
    return current_user.role == 'admin' or (product is not None and product.seller_id == current_user.id)


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def log_action(action, target_type=None, target_id=None):
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()


def validate_password_strength(password):
    issues = []
    if len(password) < 8:
        issues.append('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        issues.append('Password must include at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        issues.append('Password must include at least one lowercase letter.')
    if not re.search(r'\d', password):
        issues.append('Password must include at least one number.')
    return issues


def create_password_reset_token(user, ttl_minutes=30):
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)

    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).delete()
    db.session.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
    )
    db.session.commit()
    return raw_token


def find_active_password_reset_token(raw_token):
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    token_record = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    if not token_record:
        return None
    if token_record.used_at is not None:
        return None
    if token_record.expires_at < datetime.utcnow():
        return None
    return token_record


def get_settings_cipher():
    configured_key = os.getenv('ALERT_SETTINGS_ENC_KEY', '').strip()

    if configured_key:
        try:
            return Fernet(configured_key.encode('utf-8'))
        except Exception:
            app.logger.warning('Invalid ALERT_SETTINGS_ENC_KEY; falling back to derived key.')

    # Derive a stable fallback key from app secret for local development.
    digest = hashlib.sha256(app.secret_key.encode('utf-8')).digest()
    derived_key = base64.urlsafe_b64encode(digest)
    return Fernet(derived_key)


def encrypt_secret(value):
    if value is None:
        return ''

    text_value = str(value)
    if text_value == '':
        return ''

    if text_value.startswith('enc::'):
        return text_value

    token = get_settings_cipher().encrypt(text_value.encode('utf-8')).decode('utf-8')
    return f'enc::{token}'


def decrypt_secret(value):
    if not value:
        return ''

    text_value = str(value)
    if not text_value.startswith('enc::'):
        return text_value

    token = text_value[5:]
    try:
        return get_settings_cipher().decrypt(token.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        app.logger.warning('Failed to decrypt stored setting token.')
        return ''


def get_setting(key, default=''):
    setting = SystemSetting.query.filter_by(key=key).first()
    if setting and setting.value is not None and setting.value != '':
        if key in SENSITIVE_SETTING_KEYS:
            decrypted_value = decrypt_secret(setting.value)
            app.config[key] = decrypted_value
            return decrypted_value
        if key in ('SMTP_PORT', 'ALERT_MIN_INTERVAL_MINUTES', 'ALERT_ESCALATION_DROP_STEP'):
            try:
                return int(setting.value)
            except ValueError:
                defaults = {
                    'SMTP_PORT': 587,
                    'ALERT_MIN_INTERVAL_MINUTES': 240,
                    'ALERT_ESCALATION_DROP_STEP': 2,
                }
                return defaults.get(key, default)
        if key in ('SMTP_USE_TLS', 'ALERT_EMAIL_ENABLED', 'ALERT_WHATSAPP_ENABLED'):
            return parse_bool(setting.value, default=True)
        return setting.value
    return app.config.get(key, default)


def save_setting(key, value):
    raw_value = '' if value is None else str(value)
    setting = SystemSetting.query.filter_by(key=key).first()
    if not setting:
        setting = SystemSetting(key=key)
        db.session.add(setting)

    if key in SENSITIVE_SETTING_KEYS:
        setting.value = encrypt_secret(raw_value)
        app.config[key] = raw_value
        return

    setting.value = raw_value

    if key in ('SMTP_PORT', 'ALERT_MIN_INTERVAL_MINUTES', 'ALERT_ESCALATION_DROP_STEP'):
        try:
            app.config[key] = int(setting.value or '587')
        except ValueError:
            defaults = {
                'SMTP_PORT': 587,
                'ALERT_MIN_INTERVAL_MINUTES': 240,
                'ALERT_ESCALATION_DROP_STEP': 2,
            }
            app.config[key] = defaults.get(key, 0)
    elif key in ('SMTP_USE_TLS', 'ALERT_EMAIL_ENABLED', 'ALERT_WHATSAPP_ENABLED'):
        app.config[key] = parse_bool(setting.value, default=True)
    else:
        app.config[key] = setting.value


def save_setting_if_present(key, value):
    if key in SENSITIVE_SETTING_KEYS and (value is None or str(value).strip() == ''):
        return
    save_setting(key, value)


def record_alert(channel, status, message, details=''):
    log = AlertLog(channel=channel, status=status, message=message, details=details)
    db.session.add(log)
    db.session.commit()


def record_sale(seller_id, product_id, quantity, total_price):
    sale = Sale(
        seller_id=seller_id,
        product_id=product_id,
        quantity=quantity,
        total_price=total_price,
    )
    db.session.add(sale)


def record_product_views(seller_id, products):
    for product in products:
        db.session.add(ProductView(seller_id=seller_id, product_id=product.id))


def sync_orders_payment_status(reference, payment_status):
    if not reference:
        return 0

    matched_orders = Order.query.filter_by(payment_reference=reference).all()
    for order in matched_orders:
        order.payment_status = payment_status

    if matched_orders:
        db.session.commit()

    return len(matched_orders)


def build_cart_items():
    cart_data = session.get('cart', {})
    normalized_cart = {}
    items = []
    total = 0.0

    for product_id, quantity in cart_data.items():
        try:
            numeric_product_id = int(product_id)
            numeric_quantity = int(quantity)
        except (TypeError, ValueError):
            continue

        product = db.session.get(Product, numeric_product_id)
        if not product or numeric_quantity <= 0 or not product.seller_id or not product.is_active:
            continue

        if product.quantity <= 0:
            continue

        clamped_quantity = min(numeric_quantity, product.quantity)
        normalized_cart[str(product.id)] = clamped_quantity
        subtotal = product.price * clamped_quantity
        total += subtotal
        items.append({
            'product': product,
            'quantity': clamped_quantity,
            'subtotal': subtotal,
        })

    session['cart'] = normalized_cart
    session.modified = True
    return items, total


def get_cart_count():
    cart_data = session.get('cart', {})
    count = 0
    for quantity in cart_data.values():
        try:
            count += int(quantity)
        except (TypeError, ValueError):
            continue
    return count


@app.context_processor
def inject_cart_meta():
    return {'cart_count': get_cart_count()}


def build_low_stock_message(products):
    lines = ["AutoSeller Ghana Alert", "", "Low stock detected:"]
    for product in products:
        lines.append(f"{product.name} - Quantity: {product.quantity}")
    lines.extend(["", "Please reorder inventory."])
    return "\n".join(lines)


def normalize_whatsapp_number(raw_value):
    if not raw_value:
        return ''

    value = str(raw_value).strip()
    if value.startswith('whatsapp:'):
        value = value.split(':', 1)[1]

    # wa.me expects only digits without plus sign or spaces.
    if value.startswith('+'):
        value = value[1:]

    return ''.join(ch for ch in value if ch.isdigit())


def is_allowed_image(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_IMAGE_EXTENSIONS


def save_uploaded_product_image(file_storage):
    if not file_storage or not file_storage.filename:
        return '', None

    if not is_allowed_image(file_storage.filename):
        return '', 'Invalid image format. Use PNG, JPG, JPEG, WEBP, or GIF.'

    os.makedirs(app.config['PRODUCT_UPLOAD_DIR'], exist_ok=True)
    safe_name = secure_filename(file_storage.filename)
    ext = safe_name.rsplit('.', 1)[1].lower()
    target_ext = 'jpg' if ext == 'jpeg' else ext
    unique_name = f"product_{uuid4().hex}.{target_ext}"
    full_path = os.path.join(app.config['PRODUCT_UPLOAD_DIR'], unique_name)

    if PIL_AVAILABLE:
        try:
            with Image.open(file_storage.stream) as image:
                image = ImageOps.exif_transpose(image)
                max_side = int(app.config.get('PRODUCT_IMAGE_MAX_SIDE', 1400))
                image.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)

                if target_ext in ('jpg', 'jpeg'):
                    if image.mode not in ('RGB', 'L'):
                        image = image.convert('RGB')
                    image.save(
                        full_path,
                        format='JPEG',
                        quality=int(app.config.get('PRODUCT_IMAGE_JPEG_QUALITY', 82)),
                        optimize=True,
                        progressive=True,
                    )
                elif target_ext == 'webp':
                    image.save(full_path, format='WEBP', quality=82, method=6)
                elif target_ext == 'png':
                    image.save(full_path, format='PNG', optimize=True)
                else:
                    image.save(full_path)

            return f"/static/uploads/{unique_name}", None
        except Exception:
            # Fall back to raw save if image optimization fails for any reason.
            file_storage.stream.seek(0)

    file_storage.save(full_path)
    return f"/static/uploads/{unique_name}", None


def open_smtp_connection(smtp_host, smtp_port, timeout=20):
    try:
        return smtplib.SMTP(smtp_host, smtp_port, timeout=timeout)
    except OSError as exc:
        # Some hosts fail on IPv6 route selection (Errno 101). Retry with IPv4.
        if getattr(exc, 'errno', None) != 101:
            raise

        addr_info = socket.getaddrinfo(smtp_host, smtp_port, socket.AF_INET, socket.SOCK_STREAM)
        if not addr_info:
            raise

        last_error = exc
        for info in addr_info:
            ip_addr = info[4][0]
            client = smtplib.SMTP(timeout=timeout)
            try:
                client.connect(ip_addr, smtp_port)
                # Keep original host for EHLO/TLS context even when connected via IP.
                client._host = smtp_host
                return client
            except OSError as inner_exc:
                last_error = inner_exc
                try:
                    client.close()
                except Exception:
                    pass

        raise last_error


def send_low_stock_email(message):
    if not get_setting('ALERT_EMAIL_ENABLED', True):
        return 'skipped', 'Email alerts are disabled in settings.'

    smtp_host = get_setting('SMTP_HOST', '')
    email_from = get_setting('ALERT_EMAIL_FROM', '')
    email_to = get_setting('ALERT_EMAIL_TO', '')

    missing = [name for name, val in [('SMTP Host', smtp_host), ('Email From', email_from), ('Email To', email_to)] if not val]
    if missing:
        return 'skipped', f'Missing: {", ".join(missing)}'

    try:
        msg = EmailMessage()
        msg['Subject'] = 'AutoSeller Ghana Low-Stock Alert'
        msg['From'] = email_from
        msg['To'] = email_to
        msg.set_content(message)

        smtp_port = get_setting('SMTP_PORT', 587)
        smtp_use_tls = get_setting('SMTP_USE_TLS', True)

        with open_smtp_connection(smtp_host, smtp_port, timeout=20) as smtp:
            if smtp_use_tls:
                smtp.starttls()

            username = get_setting('SMTP_USERNAME', '')
            password = get_setting('SMTP_PASSWORD', '')
            if username and password:
                smtp.login(username, password)

            smtp.send_message(msg)

        return 'sent', 'Email sent successfully.'
    except Exception as exc:
        app.logger.exception('Failed to send low-stock email alert.')
        return 'failed', str(exc)


def send_password_reset_email(user, reset_link):
    smtp_host = get_setting('SMTP_HOST', '')
    email_from = get_setting('ALERT_EMAIL_FROM', '')
    recipient = (user.email or '').strip().lower()

    if not recipient:
        return 'skipped', 'This account does not have an email address.'

    if not smtp_host or not email_from:
        return 'skipped', 'SMTP email settings are incomplete.'

    try:
        msg = EmailMessage()
        msg['Subject'] = 'AutoSeller Ghana Password Reset'
        msg['From'] = email_from
        msg['To'] = recipient
        msg.set_content(
            'Hello,\n\n'
            'We received a request to reset your AutoSeller Ghana password.\n\n'
            f'Reset your password here: {reset_link}\n\n'
            'This link expires in 30 minutes. If you did not request this, you can ignore this email.'
        )

        smtp_port = get_setting('SMTP_PORT', 587)
        smtp_use_tls = get_setting('SMTP_USE_TLS', True)

        with open_smtp_connection(smtp_host, smtp_port, timeout=20) as smtp:
            if smtp_use_tls:
                smtp.starttls()

            username = get_setting('SMTP_USERNAME', '')
            password = get_setting('SMTP_PASSWORD', '')
            if username and password:
                smtp.login(username, password)

            smtp.send_message(msg)

        return 'sent', f'Reset link sent to {recipient}.'
    except Exception as exc:
        app.logger.exception('Failed to send password reset email.')
        return 'failed', str(exc)


def send_basic_email(to_email, subject, body):
    smtp_host = get_setting('SMTP_HOST', '')
    email_from = get_setting('ALERT_EMAIL_FROM', '')

    if not smtp_host or not email_from or not to_email:
        return 'skipped', 'Missing SMTP Host, Email From, or recipient email.'

    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_from
        msg['To'] = to_email
        msg.set_content(body)

        smtp_port = get_setting('SMTP_PORT', 587)
        smtp_use_tls = get_setting('SMTP_USE_TLS', True)

        with open_smtp_connection(smtp_host, smtp_port, timeout=20) as smtp:
            if smtp_use_tls:
                smtp.starttls()

            username = get_setting('SMTP_USERNAME', '')
            password = get_setting('SMTP_PASSWORD', '')
            if username and password:
                smtp.login(username, password)

            smtp.send_message(msg)

        return 'sent', 'Email sent.'
    except Exception as exc:
        app.logger.exception('Failed to send generic email.')
        return 'failed', str(exc)


def find_market_signal_sellers(category):
    query = User.query.filter(User.is_approved.is_(True), User.role.in_(['admin', 'staff']))
    sellers = query.all()

    if not category:
        return sellers

    category_lower = category.strip().lower()
    matched_ids = {
        row[0]
        for row in db.session.query(Product.seller_id)
        .filter(Product.is_active.is_(True), Product.category.isnot(None), func.lower(Product.category) == category_lower)
        .all()
        if row[0] is not None
    }

    matched_sellers = [seller for seller in sellers if seller.id in matched_ids]
    return matched_sellers if matched_sellers else sellers


def notify_market_signal_sellers(signal_request):
    sellers = find_market_signal_sellers(signal_request.category)
    delivered = 0

    for seller in sellers:
        recipient = (seller.email or '').strip().lower()
        if not recipient:
            continue

        subject = 'New Market Signal request on AutoSeller Ghana'
        body = (
            'A buyer has posted a new request.\n\n'
            f'Request: {signal_request.request_text}\n'
            f'Category: {signal_request.category or "Not specified"}\n'
            f'Location: {signal_request.location or "Not specified"}\n\n'
            'Log in to respond quickly from your Market Signal board.'
        )
        status, _ = send_basic_email(recipient, subject, body)
        if status == 'sent':
            delivered += 1

    return delivered, len(sellers)


MARKET_SIGNAL_INTENT_KEYWORDS = (
    'where can i get',
    'where can i buy',
    'who sells',
    'i need',
    'looking for',
    'where to get',
)


def looks_like_market_signal_intent(search_text):
    normalized = (search_text or '').strip().lower()
    if len(normalized) < 8:
        return False
    return any(keyword in normalized for keyword in MARKET_SIGNAL_INTENT_KEYWORDS)


def infer_market_signal_category(search_text):
    text_lower = (search_text or '').strip().lower()
    if not text_lower:
        return None

    categories = [
        row[0]
        for row in db.session.query(Product.category)
        .filter(Product.category.isnot(None), Product.category != '')
        .distinct()
        .all()
    ]

    for category in categories:
        candidate = (category or '').strip()
        if candidate and candidate.lower() in text_lower:
            return candidate

    return None


def infer_market_signal_location(search_text):
    text = (search_text or '').strip()
    if not text:
        return None

    match = re.search(r'\bin\s+([a-zA-Z][a-zA-Z\s\-]{1,40})', text, flags=re.IGNORECASE)
    if not match:
        return None

    location = match.group(1).strip(' .,!?:;')
    return location[:60] if location else None


def create_market_signal_from_search(search_text):
    normalized_text = (search_text or '').strip()
    if not looks_like_market_signal_intent(normalized_text):
        return None

    now = datetime.utcnow()
    duplicate_cutoff = now - timedelta(minutes=20)
    duplicate = MarketRequest.query.filter(
        func.lower(MarketRequest.request_text) == normalized_text.lower(),
        MarketRequest.created_at >= duplicate_cutoff,
    ).first()

    if duplicate:
        return {
            'created': False,
            'request': duplicate,
            'delivered': 0,
            'total_candidates': 0,
            'reason': 'duplicate_recent',
        }

    signal_request = MarketRequest(
        user_id=current_user.id if current_user.is_authenticated else None,
        requester_name=current_user.username if current_user.is_authenticated else None,
        requester_contact=current_user.email if current_user.is_authenticated else None,
        request_text=normalized_text,
        category=infer_market_signal_category(normalized_text),
        location=infer_market_signal_location(normalized_text),
        status='open',
    )
    db.session.add(signal_request)
    db.session.commit()

    delivered, total_candidates = notify_market_signal_sellers(signal_request)
    return {
        'created': True,
        'request': signal_request,
        'delivered': delivered,
        'total_candidates': total_candidates,
        'reason': 'created',
    }


def send_low_stock_whatsapp(message):
    if not get_setting('ALERT_WHATSAPP_ENABLED', True):
        return 'skipped', 'WhatsApp alerts are disabled in settings.'

    sid = get_setting('TWILIO_ACCOUNT_SID', '')
    token = get_setting('TWILIO_AUTH_TOKEN', '')
    from_number = get_setting('TWILIO_WHATSAPP_FROM', '')
    to_number = get_setting('ALERT_WHATSAPP_TO', '')

    if not sid or not token or not from_number or not to_number:
        return 'skipped', 'WhatsApp settings are incomplete.'

    try:
        from twilio.rest import Client
    except ImportError:
        app.logger.warning('Twilio package not installed; skipping WhatsApp low-stock alert.')
        return 'skipped', 'Twilio package is not installed.'

    try:
        client = Client(sid, token)
        client.messages.create(body=message, from_=from_number, to=to_number)
        return 'sent', 'WhatsApp message sent successfully.'
    except Exception as exc:
        app.logger.exception('Failed to send low-stock WhatsApp alert.')
        return 'failed', str(exc)


def check_low_stock():
    with app.app_context():
        low_products = Product.query.filter(Product.is_active.is_(True), Product.quantity <= Product.low_stock_threshold)\
            .order_by(Product.name.asc()).all()

        min_interval = int(get_setting('ALERT_MIN_INTERVAL_MINUTES', 240) or 240)
        drop_step = int(get_setting('ALERT_ESCALATION_DROP_STEP', 2) or 2)
        now = datetime.utcnow()
        current_ids = {product.id for product in low_products}

        stale_states = LowStockAlertState.query.all()
        for state in stale_states:
            if state.product_id not in current_ids:
                db.session.delete(state)

        changed_products = []
        for product in low_products:
            state = LowStockAlertState.query.filter_by(product_id=product.id).first()

            should_notify = state is None
            if state and state.last_alert_at:
                elapsed_mins = (now - state.last_alert_at).total_seconds() / 60
                if elapsed_mins >= min_interval:
                    should_notify = True

            if state and product.quantity <= (state.last_alert_quantity - drop_step):
                should_notify = True

            if should_notify:
                changed_products.append(product)

        if not changed_products:
            db.session.commit()
            return

        message = build_low_stock_message(changed_products)
        print(message)

        email_status, email_details = send_low_stock_email(message)
        whatsapp_status, whatsapp_details = send_low_stock_whatsapp(message)

        record_alert('terminal', 'sent', message, 'Printed to terminal output.')
        record_alert('email', email_status, message, email_details)
        record_alert('whatsapp', whatsapp_status, message, whatsapp_details)

        if email_status != 'sent' and whatsapp_status != 'sent':
            app.logger.info('Low-stock alert printed to terminal only (email/WhatsApp not configured).')

        for product in changed_products:
            state = LowStockAlertState.query.filter_by(product_id=product.id).first()
            if not state:
                state = LowStockAlertState(product_id=product.id)
                db.session.add(state)

            state.last_alert_quantity = product.quantity
            state.last_alert_at = now

        db.session.commit()


@app.route('/')
def home():
    if not current_user.is_authenticated:
        featured_products = Product.query.filter(
            Product.is_active.is_(True),
            Product.quantity > 0,
            Product.seller_id.isnot(None)
        ).order_by(Product.created_at.desc()).limit(8).all()

        trending_cutoff = datetime.utcnow() - timedelta(days=7)
        trending_stores = db.session.query(
            User.id, User.username, User.store_name, User.store_slug, User.store_logo,
            func.count(Sale.id).label('sale_count')
        ).join(Sale, User.id == Sale.seller_id).filter(
            Sale.sale_date >= trending_cutoff,
            User.is_approved.is_(True)
        ).group_by(User.id).order_by(desc('sale_count')).limit(6).all()

        return render_template('landing.html', featured_products=featured_products, trending_stores=trending_stores)

    search = request.args.get('search', '').strip()
    query = Product.query.filter(Product.seller_id == current_user.id)
    if search:
        query = query.filter(Product.name.ilike(f"%{search}%"))
        products = query.order_by(Product.created_at.desc()).all()
    else:
        products = query.order_by(Product.created_at.desc()).all()
    return render_template('index.html', products=products, search=search)


@app.route('/marketplace')
def marketplace():
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 16
    query = Product.query.filter(
        Product.is_active.is_(True),
        Product.quantity > 0,
        Product.seller_id.isnot(None)
    ).order_by(Product.created_at.desc())
    auto_signal_result = None
    if search:
        query = query.filter(Product.name.ilike(f"%{search}%"))
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    products = pagination.items

    should_auto_signal = request.args.get('auto_signal', '1') == '1'
    if search and not products and page == 1 and should_auto_signal:
        auto_signal_result = create_market_signal_from_search(search)

    return render_template(
        'marketplace.html',
        products=products,
        search=search,
        pagination=pagination,
        auto_signal_result=auto_signal_result,
    )


@app.route('/market-signal', methods=['GET', 'POST'])
def market_signal():
    if request.method == 'POST':
        request_text = request.form.get('request_text', '').strip()
        category = request.form.get('category', '').strip()
        location = request.form.get('location', '').strip()
        requester_name = request.form.get('requester_name', '').strip()
        requester_contact = request.form.get('requester_contact', '').strip()

        if not request_text:
            flash('Tell sellers what you need.', 'danger')
            return redirect(url_for('market_signal'))

        if len(request_text) < 8:
            flash('Request should be at least 8 characters.', 'danger')
            return redirect(url_for('market_signal'))

        signal_request = MarketRequest(
            user_id=current_user.id if current_user.is_authenticated else None,
            requester_name=requester_name or (current_user.username if current_user.is_authenticated else None),
            requester_contact=requester_contact,
            request_text=request_text,
            category=category or None,
            location=location or None,
            status='open',
        )
        db.session.add(signal_request)
        db.session.commit()

        delivered, total_candidates = notify_market_signal_sellers(signal_request)
        flash(
            f'Market Signal sent. {delivered} of {total_candidates} seller alert emails delivered.',
            'success' if delivered > 0 else 'danger'
        )
        return redirect(url_for('market_signal'))

    categories = [
        row[0]
        for row in db.session.query(Product.category)
        .filter(Product.category.isnot(None), Product.category != '')
        .distinct()
        .order_by(Product.category.asc())
        .all()
    ]
    recent_requests = MarketRequest.query.order_by(MarketRequest.created_at.desc()).limit(20).all()

    prefill = {
        'request_text': request.args.get('request_text', '').strip(),
        'category': request.args.get('category', '').strip(),
        'location': request.args.get('location', '').strip(),
    }
    return render_template(
        'market_signal.html',
        categories=categories,
        recent_requests=recent_requests,
        prefill=prefill,
    )


@app.route('/market-signal/board')
@login_required
@role_required('admin', 'staff')
def market_signal_board():
    status_filter = (request.args.get('status', 'open') or 'open').strip().lower()
    if status_filter not in ('open', 'closed', 'all'):
        status_filter = 'open'

    query = MarketRequest.query
    if status_filter in ('open', 'closed'):
        query = query.filter(MarketRequest.status == status_filter)

    requests_list = query.order_by(MarketRequest.created_at.desc()).limit(150).all()
    return render_template('market_signal_board.html', requests_list=requests_list, status_filter=status_filter)


@app.route('/market-signal/respond/<int:request_id>', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def respond_market_signal(request_id):
    signal_request = MarketRequest.query.get_or_404(request_id)
    message = request.form.get('message', '').strip()
    price_raw = request.form.get('price', '').strip()
    close_request = request.form.get('close_request') == '1'

    if signal_request.status == 'closed':
        flash('This request is already closed.', 'danger')
        return redirect(url_for('market_signal_board'))

    if not message:
        flash('Response message is required.', 'danger')
        return redirect(url_for('market_signal_board'))

    price = None
    if price_raw:
        try:
            price = float(price_raw)
            if price < 0:
                raise ValueError
        except ValueError:
            flash('Price must be a valid non-negative number.', 'danger')
            return redirect(url_for('market_signal_board'))

    response = RequestResponse(
        request_id=signal_request.id,
        seller_id=current_user.id,
        message=message,
        price=price,
    )
    db.session.add(response)

    if close_request:
        signal_request.status = 'closed'

    db.session.commit()
    log_action('responded market signal', 'market_request', signal_request.id)
    flash('Response sent successfully.', 'success')
    return redirect(url_for('market_signal_board'))


@app.route('/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    product = Product.query.filter(
        Product.id == product_id,
        Product.is_active.is_(True),
        Product.quantity > 0
    ).first_or_404()
    cart = session.get('cart', {})
    product_key = str(product.id)

    if product_key in cart:
        cart[product_key] = min(int(cart[product_key]) + 1, product.quantity)
    else:
        cart[product_key] = 1

    session['cart'] = cart
    flash(f'{product.name} added to cart.', 'success')
    return redirect(url_for('marketplace'))


@app.route('/cart')
def cart():
    items, total = build_cart_items()
    return render_template('cart.html', products=items, total=total)


@app.route('/clear-cart')
def clear_cart():
    session['cart'] = {}
    session.modified = True
    flash('Cart cleared.', 'success')
    return redirect(url_for('cart'))


@app.route('/cart/update/<int:product_id>', methods=['POST'])
def update_cart_item(product_id):
    cart = session.get('cart', {})
    product_key = str(product_id)
    product = db.session.get(Product, product_id)

    if product_key not in cart or not product:
        flash('Cart item not found.', 'danger')
        return redirect(url_for('cart'))

    try:
        quantity = int(request.form.get('quantity', '1'))
    except (TypeError, ValueError):
        quantity = 1

    if quantity <= 0:
        cart.pop(product_key, None)
        flash(f'{product.name} removed from cart.', 'success')
    else:
        cart[product_key] = min(quantity, max(product.quantity, 1))
        flash(f'{product.name} quantity updated.', 'success')

    session['cart'] = cart
    return redirect(url_for('cart'))


@app.route('/cart/remove/<int:product_id>', methods=['POST'])
def remove_cart_item(product_id):
    cart = session.get('cart', {})
    product_key = str(product_id)
    product = db.session.get(Product, product_id)

    if product_key in cart:
        cart.pop(product_key, None)
        session['cart'] = cart
        flash(f'{product.name if product else "Item"} removed from cart.', 'success')

    return redirect(url_for('cart'))


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.filter(
        Product.id == product_id,
        Product.is_active.is_(True),
        Product.seller_id.isnot(None)
    ).first_or_404()
    seller = product.seller
    related_products = []

    if product.category:
        related_products = Product.query.filter(
            Product.is_active.is_(True),
            Product.quantity > 0,
            Product.category == product.category,
            Product.id != product.id,
        ).order_by(Product.created_at.desc()).limit(4).all()

    if not related_products and seller:
        related_products = Product.query.filter(
            Product.is_active.is_(True),
            Product.quantity > 0,
            Product.seller_id == seller.id,
            Product.id != product.id,
        ).order_by(Product.created_at.desc()).limit(4).all()

    if seller:
        record_product_views(seller.id, [product])
        db.session.commit()
    return render_template('product_detail.html', product=product, seller=seller, related_products=related_products)


@app.route('/checkout', methods=['POST'])
def checkout():
    customer_name = request.form.get('customer_name', '').strip()
    customer_contact = request.form.get('customer_contact', '').strip()
    customer_address = request.form.get('customer_address', '').strip()

    if not customer_name or not customer_contact:
        flash('Name and phone are required for checkout.', 'danger')
        return redirect(url_for('cart'))

    items, total = build_cart_items()
    if not items:
        flash('Your cart is empty.', 'danger')
        return redirect(url_for('cart'))

    for item in items:
        product = item['product']
        quantity = item['quantity']
        if quantity > product.quantity:
            flash(f'Only {product.quantity} item(s) available for {product.name}.', 'danger')
            return redirect(url_for('cart'))

    paystack_key = get_setting('PAYSTACK_PUBLIC_KEY', '')
    use_paystack = request.form.get('pay_with_paystack') == '1'
    paystack_enabled = bool(paystack_key and use_paystack)
    paystack_reference = f"ASGH_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}" if paystack_enabled else None

    created_orders = 0
    summary_lines = []
    for item in items:
        product = item['product']
        quantity = item['quantity']
        subtotal = item['subtotal']
        order = Order(
            product_id=product.id,
            customer_name=customer_name,
            customer_contact=customer_contact,
            customer_address=customer_address,
            quantity=quantity,
            total_price=subtotal,
            status='Pending',
            payment_status='pending',
            payment_reference=paystack_reference,
        )
        db.session.add(order)
        record_sale(
            seller_id=product.seller_id,
            product_id=product.id,
            quantity=quantity,
            total_price=subtotal,
        )
        product.quantity -= quantity
        if product.quantity < 0:
            product.quantity = 0
        created_orders += 1
        summary_lines.append(f'- {product.name} x{quantity} (GHS {subtotal:.2f})')

    db.session.commit()
    session['cart'] = {}
    session.modified = True
    flash(f'Checkout complete. {created_orders} order(s) created. Total: GHS {total:.2f}', 'success')

    # Paystack payment option: redirect to Paystack if configured and selected.
    if paystack_enabled:
        paystack_amount = int(total * 100)  # Paystack expects kobo/pesewas (smallest unit)
        return redirect(url_for(
            'paystack_pay',
            amount=paystack_amount,
            email=customer_contact,
            name=customer_name,
            reference=paystack_reference,
        ))

    whatsapp_digits = normalize_whatsapp_number(get_setting('ALERT_WHATSAPP_TO', ''))
    if whatsapp_digits:
        message = (
            'Hello, I just placed an order on AutoSeller Ghana.\n\n'
            f'Customer: {customer_name}\n'
            f'Phone: {customer_contact}\n'
            f'Total: GHS {total:.2f}\n\n'
            'Items:\n' + '\n'.join(summary_lines)
        )
        if customer_address:
            message += f'\n\nAddress: {customer_address}'
        return redirect(f'https://wa.me/{whatsapp_digits}?text={quote_plus(message)}')

    return redirect(url_for('marketplace'))


@app.route('/paystack/pay')
def paystack_pay():
    paystack_key = get_setting('PAYSTACK_PUBLIC_KEY', '')
    amount = request.args.get('amount', 0, type=int)
    email = request.args.get('email', '')
    name = request.args.get('name', '')
    reference = request.args.get('reference', '')
    return render_template('paystack_pay.html',
        paystack_key=paystack_key,
        amount=amount,
        email=email,
        name=name,
        reference=reference,
    )


@app.route('/paystack/callback')
def paystack_callback():
    # After Paystack redirects back, verify the transaction server-side if secret key is set.
    reference = request.args.get('reference', '').strip()
    paystack_secret = get_setting('PAYSTACK_SECRET_KEY', '')

    if reference and paystack_secret:
        import urllib.request as _urllib_req
        try:
            req = _urllib_req.Request(
                f'https://api.paystack.co/transaction/verify/{reference}',
                headers={'Authorization': f'Bearer {paystack_secret}'},
            )
            with _urllib_req.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            status = data.get('data', {}).get('status', '')
            if status == 'success':
                sync_orders_payment_status(reference, 'paid')
                flash('Payment verified! Your order is confirmed.', 'success')
            else:
                sync_orders_payment_status(reference, 'failed')
                flash(f'Payment status: {status}. Contact support if charged.', 'warning')
        except Exception:
            flash('Could not verify payment. Please contact support with your reference.', 'warning')
    else:
        flash('Order placed. Payment reference: ' + (reference or 'N/A'), 'success')

    return redirect(url_for('marketplace'))


@app.route('/paystack/webhook', methods=['POST'])
def paystack_webhook():
    paystack_secret = get_setting('PAYSTACK_SECRET_KEY', '')
    if not paystack_secret:
        return 'Webhook not configured', 503

    payload = request.get_data() or b''
    signature = request.headers.get('x-paystack-signature', '')
    expected = hmac.new(paystack_secret.encode('utf-8'), payload, hashlib.sha512).hexdigest()

    if not signature or not hmac.compare_digest(signature, expected):
        return 'Invalid signature', 401

    try:
        event = json.loads(payload.decode('utf-8'))
    except ValueError:
        return 'Invalid payload', 400

    event_name = event.get('event', '')
    event_data = event.get('data', {}) or {}
    reference = event_data.get('reference', '')

    if event_name == 'charge.success':
        sync_orders_payment_status(reference, 'paid')
    elif event_name in ('charge.failed', 'charge.abandoned'):
        sync_orders_payment_status(reference, 'failed')
    elif event_name in ('refund.success', 'refund.processed'):
        sync_orders_payment_status(reference, 'refunded')

    return 'ok', 200


@app.route('/market')
def market():
    search = request.args.get('search', '').strip()
    if search:
        return redirect(url_for('marketplace', search=search))
    return redirect(url_for('marketplace'))


@app.route('/shop/<seller_username>')
def public_shop(seller_username):
    seller = User.query.filter(User.username.ilike(seller_username)).first()
    if not seller:
        abort(404)

    if seller.store_slug:
        return redirect(url_for('seller_store', slug=seller.store_slug))

    products = Product.query.filter(
        Product.seller_id == seller.id,
        Product.is_active.is_(True),
        Product.quantity > 0
    ).order_by(Product.created_at.desc()).all()
    record_product_views(seller.id, products)
    db.session.commit()

    whatsapp_digits = normalize_whatsapp_number(get_setting('ALERT_WHATSAPP_TO', ''))
    share_url = url_for('public_shop', seller_username=seller.username, _external=True)

    return render_template(
        'shop.html',
        seller=seller,
        products=products,
        whatsapp_digits=whatsapp_digits,
        share_url=share_url,
        message=request.args.get('message', ''),
        kind=request.args.get('kind', 'info'),
    )


@app.route('/shop/<seller_username>/order/<int:product_id>', methods=['POST'])
def create_public_order(seller_username, product_id):
    seller = User.query.filter(User.username.ilike(seller_username)).first()
    if not seller:
        abort(404)

    product = Product.query.get_or_404(product_id)
    if product.seller_id != seller.id:
        abort(404)
    if not product.is_active:
        msg = 'This product is no longer available.'
        return redirect(url_for('public_shop', seller_username=seller.username, kind='danger', message=msg))
    customer_name = request.form.get('name', '').strip()
    customer_phone = request.form.get('phone', '').strip()
    customer_address = request.form.get('address', '').strip()

    try:
        quantity = int(request.form.get('quantity', '1'))
    except (ValueError, TypeError):
        quantity = 0

    if not customer_name or not customer_phone:
        msg = 'Name and phone are required to place an order.'
        return redirect(url_for('public_shop', seller_username=seller.username, kind='danger', message=msg))

    if quantity <= 0:
        msg = 'Quantity must be at least 1.'
        return redirect(url_for('public_shop', seller_username=seller.username, kind='danger', message=msg))

    if quantity > product.quantity:
        msg = f"Only {product.quantity} item(s) available for {product.name}."
        return redirect(url_for('public_shop', seller_username=seller.username, kind='danger', message=msg))

    total_price = product.price * quantity
    order = Order(
        product_id=product.id,
        customer_name=customer_name,
        customer_contact=customer_phone,
        customer_address=customer_address,
        quantity=quantity,
        total_price=total_price,
        status='Pending',
    )
    db.session.add(order)
    record_sale(
        seller_id=seller.id,
        product_id=product.id,
        quantity=quantity,
        total_price=total_price,
    )

    # Reserve stock as soon as order is captured to avoid overselling from public page.
    product.quantity -= quantity
    db.session.commit()

    seller_number = normalize_whatsapp_number(get_setting('ALERT_WHATSAPP_TO', ''))
    if not seller_number:
        msg = 'Order captured, but seller WhatsApp is not configured yet.'
        return redirect(url_for('public_shop', seller_username=seller.username, kind='warning', message=msg))

    message = (
        'New Order\n\n'
        f'Customer: {customer_name}\n'
        f'Phone: {customer_phone}\n'
        f'Product: {product.name}\n'
        f'Quantity: {quantity}\n'
        f'Price: GHS {total_price:.2f}'
    )
    if customer_address:
        message += f'\nAddress: {customer_address}'

    whatsapp_url = f"https://wa.me/{seller_number}?text={quote_plus(message)}"
    return redirect(whatsapp_url)


@app.route('/index')
def index():
    return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not getattr(user, 'is_approved', True):
                flash('Your account is pending admin approval. Please try again later.', 'danger')
                return render_template('login.html')
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid credentials.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')

        if email and User.query.filter_by(email=email).first():
            flash('Email already exists. Use another one.', 'danger')
            return render_template('register.html')

        password_issues = validate_password_strength(password)
        if password_issues:
            for issue in password_issues:
                flash(issue, 'danger')
            return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Choose another one.', 'danger')
            return render_template('register.html')

        needs_approval = app.config.get('SELF_SIGNUP_REQUIRE_APPROVAL', False)
        slug = generate_unique_store_slug(username)
        user = User(
            username=username,
            email=email or None,
            role='staff',
            store_slug=slug,
            store_name=username,
            store_description='',
            is_approved=not needs_approval,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if needs_approval:
            flash('Account created. Waiting for admin approval before first login.', 'success')
        else:
            flash('Account created successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/store/<slug>')
def seller_store(slug):
    seller = User.query.filter_by(store_slug=slug).first_or_404()
    products = Product.query.filter(
        Product.seller_id == seller.id,
        Product.is_active.is_(True),
        Product.quantity > 0
    ).order_by(Product.created_at.desc()).all()
    record_product_views(seller.id, products)
    db.session.commit()

    return render_template(
        'store.html',
        seller=seller,
        products=products,
        share_url=url_for('seller_store', slug=seller.store_slug, _external=True),
        message=request.args.get('message', ''),
        kind=request.args.get('kind', 'info'),
    )


@app.route('/add', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def add_product():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        image_url = request.form.get('image_url', '').strip()
        image_file = request.files.get('image_file')
        price_val = request.form.get('price', '').strip()
        quantity_val = request.form.get('quantity', '').strip()

        errors = []
        if not name:
            errors.append('Product name is required.')

        try:
            price = float(price_val)
            if price < 0:
                errors.append('Price must be zero or positive.')
        except (ValueError, TypeError):
            errors.append('A valid price is required.')

        try:
            qty = int(quantity_val)
            if qty < 0:
                errors.append('Quantity must be zero or positive.')
        except (ValueError, TypeError):
            errors.append('A valid quantity is required.')

        uploaded_image_url, upload_error = save_uploaded_product_image(image_file)
        if upload_error:
            errors.append(upload_error)
        if uploaded_image_url:
            image_url = uploaded_image_url

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template(
                'add_product.html',
                name=name,
                description=description,
                category=category,
                image_url=image_url,
                price=price_val,
                quantity=quantity_val,
            )

        prod = Product(
            seller_id=current_user.id,
            name=name,
            description=description,
            category=category or None,
            image_url=image_url,
            price=price,
            quantity=qty,
        )
        db.session.add(prod)
        db.session.commit()
        log_action('created product', 'product', prod.id)
        flash('Product added successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('add_product.html')


@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'staff')
def edit_product(id):
    product = Product.query.get_or_404(id)
    if not owns_product(product):
        abort(403)
    if request.method == 'POST':
        image_file = request.files.get('image_file')
        uploaded_image_url, upload_error = save_uploaded_product_image(image_file)
        if upload_error:
            flash(upload_error, 'danger')
            return render_template('edit_product.html', product=product)

        product.name = request.form['name']
        product.price = float(request.form['price'])
        product.quantity = int(request.form['quantity'])
        product.description = request.form['description']
        product.category = request.form.get('category', '').strip() or None
        product.image_url = request.form.get('image_url', '').strip()
        if uploaded_image_url:
            product.image_url = uploaded_image_url
        db.session.commit()
        log_action('edited product', 'product', product.id)
        flash('Product updated successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('edit_product.html', product=product)


@app.route('/delete_product/<int:id>', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def delete_product(id):
    product = Product.query.get_or_404(id)
    if not owns_product(product):
        abort(403)

    has_orders = Order.query.filter_by(product_id=product.id).first() is not None
    has_sales = Sale.query.filter_by(product_id=product.id).first() is not None
    has_views = ProductView.query.filter_by(product_id=product.id).first() is not None

    if has_orders or has_sales or has_views:
        product_id = product.id
        product.is_active = False
        product.quantity = 0
        alert_state = LowStockAlertState.query.filter_by(product_id=product.id).first()
        if alert_state:
            db.session.delete(alert_state)
        db.session.commit()
        log_action('archived product', 'product', product_id)
        flash('Product has history, so it was archived instead of deleted.', 'warning')
        return redirect(url_for('home'))

    alert_state = LowStockAlertState.query.filter_by(product_id=product.id).first()
    if alert_state:
        db.session.delete(alert_state)

    product_id = product.id
    db.session.delete(product)
    db.session.commit()
    log_action('deleted product', 'product', product_id)
    flash('Product deleted successfully.', 'success')
    return redirect(url_for('home'))


@app.route('/restore_product/<int:id>', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def restore_product(id):
    product = Product.query.get_or_404(id)
    if not owns_product(product):
        abort(403)

    product.is_active = True
    db.session.commit()
    flash('Product restored. Update quantity if needed.', 'success')
    return redirect(url_for('home'))


@app.route('/add_order', methods=['GET', 'POST'])
@login_required
def add_order():
    if request.method == 'POST':
        product_id = int(request.form['product_id'])
        customer_name = request.form.get('customer_name', '').strip()
        customer_contact = request.form.get('customer_contact', '').strip()
        quantity = int(request.form.get('quantity', '1'))

        product = Product.query.filter_by(id=product_id, seller_id=current_user.id, is_active=True).first_or_404()
        total_price = product.price * quantity

        new_order = Order(
            product_id=product_id,
            customer_name=customer_name,
            customer_contact=customer_contact,
            quantity=quantity,
            total_price=total_price,
            status='Pending'
        )
        db.session.add(new_order)
        record_sale(
            seller_id=product.seller_id or current_user.id,
            product_id=product_id,
            quantity=quantity,
            total_price=total_price,
        )

        # Reduce stock after order placement
        product.quantity -= quantity
        if product.quantity < 0:
            product.quantity = 0

        db.session.commit()
        log_action('created order', 'order', new_order.id)

        flash('Order created successfully!', 'success')
        return redirect(url_for('orders'))

    products = Product.query.filter_by(seller_id=current_user.id, is_active=True).all()
    return render_template('add_order.html', products=products)


@app.route('/dashboard')
@login_required
def dashboard():
    today = date.today()

    if current_user.role == 'admin':
        products = Product.query.filter(Product.is_active.is_(True)).order_by(Product.created_at.desc()).all()
        orders_query = Order.query
        recent_alerts = AlertLog.query.order_by(AlertLog.created_at.desc()).limit(10).all()
        orders_today = Order.query.filter(func.date(Order.created_at) == today).count()
        revenue_today = db.session.query(func.sum(Order.total_price)).filter(
            func.date(Order.created_at) == today
        ).scalar() or 0
        top_products = (
            db.session.query(
                Product.name.label('name'),
                func.sum(Order.quantity).label('total_sold')
            )
            .join(Order, Order.product_id == Product.id)
            .group_by(Product.id, Product.name)
            .order_by(func.sum(Order.quantity).desc())
            .limit(5)
            .all()
        )
        recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    else:
        products = Product.query.filter_by(seller_id=current_user.id, is_active=True).order_by(Product.created_at.desc()).all()
        orders_query = Order.query.join(Product).filter(Product.seller_id == current_user.id)
        recent_alerts = []
        orders_today = (
            Order.query.join(Product)
            .filter(Product.seller_id == current_user.id, func.date(Order.created_at) == today)
            .count()
        )
        revenue_today = (
            db.session.query(func.sum(Order.total_price))
            .join(Product, Order.product_id == Product.id)
            .filter(Product.seller_id == current_user.id, func.date(Order.created_at) == today)
            .scalar() or 0
        )
        top_products = (
            db.session.query(
                Product.name.label('name'),
                func.sum(Order.quantity).label('total_sold')
            )
            .join(Order, Order.product_id == Product.id)
            .filter(Product.seller_id == current_user.id)
            .group_by(Product.id, Product.name)
            .order_by(func.sum(Order.quantity).desc())
            .limit(5)
            .all()
        )
        recent_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()

    low_stock = [p for p in products if p.quantity <= (p.low_stock_threshold or 3)]
    low_stock_products = len(low_stock)
    total_products = len(products)
    orders = orders_query.all()
    total_orders = len(orders)
    total_revenue = sum(order.total_price for order in orders)
    recent_orders = orders_query.order_by(Order.created_at.desc()).limit(5).all()
    public_shop_link = url_for('seller_store', slug=current_user.store_slug, _external=True)

    # Last 7 days trend data
    last7days_labels = [
        (datetime.today() - timedelta(days=i)).strftime('%a %d')
        for i in reversed(range(7))
    ]
    last7days_revenue = []
    last7days_orders = []
    for i in reversed(range(7)):
        day = (datetime.today() - timedelta(days=i)).date()
        if current_user.role == 'admin':
            rev = db.session.query(func.sum(Order.total_price)).filter(
                func.date(Order.created_at) == day
            ).scalar() or 0
            ords = Order.query.filter(func.date(Order.created_at) == day).count()
        else:
            rev = (
                db.session.query(func.sum(Order.total_price))
                .join(Product, Order.product_id == Product.id)
                .filter(Product.seller_id == current_user.id, func.date(Order.created_at) == day)
                .scalar() or 0
            )
            ords = (
                Order.query.join(Product)
                .filter(Product.seller_id == current_user.id, func.date(Order.created_at) == day)
                .count()
            )
        last7days_revenue.append(float(rev))
        last7days_orders.append(ords)

    return render_template(
        'dashboard.html',
        products=products,
        low_stock=low_stock,
        total_products=total_products,
        total_orders=total_orders,
        total_revenue=total_revenue,
        recent_orders=recent_orders,
        recent_alerts=recent_alerts,
        orders_today=orders_today,
        revenue_today=revenue_today,
        low_stock_products=low_stock_products,
        top_products=top_products,
        recent_logs=recent_logs,
        can_view_alert_logs=(current_user.role == 'admin'),
        public_shop_link=public_shop_link,
        seller_id=current_user.id,
        seller_name=current_user.username,
        last7days_labels=last7days_labels,
        last7days_revenue=last7days_revenue,
        last7days_orders=last7days_orders,
    )


@app.route('/orders')
@login_required
def orders():
    if current_user.role == 'admin':
        all_orders = Order.query.order_by(Order.created_at.desc()).all()
    else:
        all_orders = Order.query.join(Product).filter(Product.seller_id == current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=all_orders)


@app.route('/analytics/<int:seller_id>')
@login_required
def get_seller_analytics(seller_id):
    if current_user.id != seller_id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    trend_view = (request.args.get('view') or 'daily').strip().lower()
    if trend_view not in ('daily', 'weekly'):
        trend_view = 'daily'

    total_sales = db.session.query(func.sum(Sale.total_price)).filter(Sale.seller_id == seller_id).scalar() or 0.0
    total_orders = db.session.query(func.count(Sale.id)).filter(Sale.seller_id == seller_id).scalar() or 0

    top_products = db.session.query(
        Product.name,
        func.sum(Sale.quantity).label('sold')
    ).join(Sale, Product.id == Sale.product_id)\
        .filter(Sale.seller_id == seller_id)\
        .group_by(Product.name)\
        .order_by(desc('sold'))\
        .limit(5).all()

    views_count = db.session.query(func.count(ProductView.id)).filter(ProductView.seller_id == seller_id).scalar() or 0

    trend_cutoff = datetime.utcnow() - timedelta(days=30)
    period_expr = func.date(Sale.sale_date) if trend_view == 'daily' else func.strftime('%Y-W%W', Sale.sale_date)
    trend_rows = db.session.query(
        period_expr.label('period'),
        func.sum(Sale.total_price).label('revenue')
    ).filter(
        Sale.seller_id == seller_id,
        Sale.sale_date >= trend_cutoff,
    ).group_by(
        period_expr
    ).order_by(
        period_expr.asc()
    ).all()

    trend_labels = [str(row[0]) for row in trend_rows]
    trend_values = [float(row[1]) for row in trend_rows]
    conversion_rate = (float(total_orders) / float(views_count) * 100.0) if views_count else 0.0

    return jsonify({
        'total_sales': float(total_sales),
        'total_orders': int(total_orders),
        'top_products': [p[0] for p in top_products],
        'top_products_sales': [int(p[1]) for p in top_products],
        'total_views': int(views_count),
        'sales_trend_labels': trend_labels,
        'sales_trend_values': trend_values,
        'trend_view': trend_view,
        'conversion_rate': round(conversion_rate, 2),
    })


@app.route('/export-sales/<int:seller_id>')
@login_required
def export_sales(seller_id):
    if current_user.id != seller_id and current_user.role != 'admin':
        abort(403)
    sales = Sale.query.filter_by(seller_id=seller_id).order_by(Sale.sale_date.desc()).all()
    product_ids = list({s.product_id for s in sales})
    product_rows = Product.query.filter(Product.id.in_(product_ids)).all() if product_ids else []
    product_map = {p.id: p.name for p in product_rows}

    lines = ['Date,Product,Quantity,Total Price (GHS)']
    for s in sales:
        product_name = product_map.get(s.product_id, 'Unknown')
        # Escape CSV special characters in product names
        safe_name = product_name.replace('"', '""')
        if any(ch in safe_name for ch in [',', '"', '\n']):
            safe_name = f'"{safe_name}"'
        lines.append(f'{s.sale_date},{safe_name},{s.quantity},{s.total_price:.2f}')
    output = '\n'.join(lines)
    return Response(
        output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=sales_{seller_id}.csv'}
    )


@app.route('/low-stock-api/<int:seller_id>')
@login_required
def low_stock_api(seller_id):
    if current_user.id != seller_id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    products = Product.query.filter_by(seller_id=seller_id, is_active=True).all()
    low = [
        {'name': p.name, 'quantity': p.quantity, 'threshold': p.low_stock_threshold or 3}
        for p in products
        if p.quantity <= (p.low_stock_threshold or 3)
    ]
    return jsonify(low)


@app.route('/order_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def order_product(product_id):
    product = Product.query.filter_by(id=product_id, seller_id=current_user.id, is_active=True).first_or_404()
    if request.method == 'POST':
        customer_name = request.form.get('customer_name', '').strip()
        customer_contact = request.form.get('customer_contact', '').strip()
        quantity = int(request.form.get('quantity', '1'))

        total_price = product.price * quantity
        new_order = Order(
            product_id=product.id,
            customer_name=customer_name,
            customer_contact=customer_contact,
            quantity=quantity,
            total_price=total_price,
            status='Pending'
        )
        db.session.add(new_order)
        record_sale(
            seller_id=product.seller_id or current_user.id,
            product_id=product.id,
            quantity=quantity,
            total_price=total_price,
        )

        # Reduce stock after order placement
        product.quantity -= quantity
        if product.quantity < 0:
            product.quantity = 0

        db.session.commit()
        log_action('created order', 'order', new_order.id)
        flash('Order created successfully!', 'success')
        return redirect(url_for('orders'))

    return render_template('add_order.html', products=[product])


@app.route('/update_order/<int:order_id>', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def update_order(order_id):
    order = Order.query.get_or_404(order_id)
    if not owns_order(order):
        abort(403)
    order.status = 'Delivered'
    db.session.commit()
    flash('Order marked as Delivered.', 'success')
    return redirect(url_for('orders'))


@app.route('/update_order_status/<int:order_id>', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    if not owns_order(order):
        abort(403)
    status = request.form.get('status', 'Pending').strip().title()
    allowed = {'Pending', 'Confirmed', 'Delivered', 'Cancelled'}

    if status not in allowed:
        flash('Invalid order status selected.', 'danger')
        return redirect(url_for('orders'))

    order.status = status
    db.session.commit()
    flash(f'Order status updated to {status}.', 'success')
    return redirect(url_for('orders'))


@app.route('/delete_order/<int:order_id>', methods=['POST'])
@login_required
@role_required('admin', 'staff')
def delete_order(order_id):
    order = Order.query.get_or_404(order_id)
    if not owns_order(order):
        abort(403)
    db.session.delete(order)
    db.session.commit()
    flash('Order deleted successfully.', 'success')
    return redirect(url_for('orders'))


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


@app.route('/users')
@login_required
@role_required('admin')
def users():
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)

    query = User.query.order_by(User.id.asc())
    if search:
        query = query.filter(User.username.ilike(f"%{search}%"))

    pagination = query.paginate(page=page, per_page=5, error_out=False)
    return render_template(
        'users.html',
        users=pagination.items,
        pagination=pagination,
        search=search,
    )


@app.route('/audit-logs')
@login_required
@role_required('admin')
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return render_template('audit_logs.html', logs=logs)


@app.route('/alert_settings', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def alert_settings():
    if request.method == 'POST':
        action = request.form.get('action', 'save')
        text_keys = [
            'SMTP_HOST',
            'SMTP_PORT',
            'SMTP_USERNAME',
            'SMTP_PASSWORD',
            'ALERT_EMAIL_FROM',
            'ALERT_EMAIL_TO',
            'TWILIO_ACCOUNT_SID',
            'TWILIO_AUTH_TOKEN',
            'TWILIO_WHATSAPP_FROM',
            'ALERT_WHATSAPP_TO',
            'ALERT_MIN_INTERVAL_MINUTES',
            'ALERT_ESCALATION_DROP_STEP',
            'PAYSTACK_PUBLIC_KEY',
            'PAYSTACK_SECRET_KEY',
        ]

        for key in text_keys:
            save_setting_if_present(key, request.form.get(key, '').strip())

        save_setting('SMTP_USE_TLS', 'true' if request.form.get('SMTP_USE_TLS') else 'false')
        save_setting('ALERT_EMAIL_ENABLED', 'true' if request.form.get('ALERT_EMAIL_ENABLED') else 'false')
        save_setting('ALERT_WHATSAPP_ENABLED', 'true' if request.form.get('ALERT_WHATSAPP_ENABLED') else 'false')

        db.session.commit()

        if action in ('test', 'test_email', 'test_whatsapp'):
            test_message = (
                'AutoSeller Ghana Alert\n\n'
                'This is a test notification from Alert Settings.\n\n'
                'If you received this, your channel is configured correctly.'
            )

            email_status, email_details = 'skipped', 'Email test not requested.'
            whatsapp_status, whatsapp_details = 'skipped', 'WhatsApp test not requested.'

            if action in ('test', 'test_email'):
                email_status, email_details = send_low_stock_email(test_message)
                record_alert('email', email_status, test_message, f'TEST: {email_details}')

            if action in ('test', 'test_whatsapp'):
                whatsapp_status, whatsapp_details = send_low_stock_whatsapp(test_message)
                record_alert('whatsapp', whatsapp_status, test_message, f'TEST: {whatsapp_details}')

            flash(
                f'Test complete. Email: {email_status.upper()} ({email_details}) | '
                f'WhatsApp: {whatsapp_status.upper()} ({whatsapp_details})',
                'success' if email_status == 'sent' or whatsapp_status == 'sent' else 'danger'
            )
        else:
            flash('Alert settings updated successfully.', 'success')

        return redirect(url_for('alert_settings'))

    current_settings = {
        'SMTP_HOST': get_setting('SMTP_HOST', ''),
        'SMTP_PORT': get_setting('SMTP_PORT', 587),
        'SMTP_USERNAME': get_setting('SMTP_USERNAME', ''),
        'SMTP_PASSWORD': get_setting('SMTP_PASSWORD', ''),
        'SMTP_USE_TLS': get_setting('SMTP_USE_TLS', True),
        'ALERT_EMAIL_ENABLED': get_setting('ALERT_EMAIL_ENABLED', True),
        'ALERT_EMAIL_FROM': get_setting('ALERT_EMAIL_FROM', ''),
        'ALERT_EMAIL_TO': get_setting('ALERT_EMAIL_TO', ''),
        'TWILIO_ACCOUNT_SID': get_setting('TWILIO_ACCOUNT_SID', ''),
        'TWILIO_AUTH_TOKEN': get_setting('TWILIO_AUTH_TOKEN', ''),
        'TWILIO_WHATSAPP_FROM': get_setting('TWILIO_WHATSAPP_FROM', ''),
        'ALERT_WHATSAPP_TO': get_setting('ALERT_WHATSAPP_TO', ''),
        'ALERT_WHATSAPP_ENABLED': get_setting('ALERT_WHATSAPP_ENABLED', True),
        'ALERT_MIN_INTERVAL_MINUTES': get_setting('ALERT_MIN_INTERVAL_MINUTES', 240),
        'ALERT_ESCALATION_DROP_STEP': get_setting('ALERT_ESCALATION_DROP_STEP', 2),
        'PAYSTACK_PUBLIC_KEY': get_setting('PAYSTACK_PUBLIC_KEY', ''),
        'PAYSTACK_SECRET_KEY': get_setting('PAYSTACK_SECRET_KEY', ''),
    }
    return render_template('alert_settings.html', settings=current_settings)


@app.route('/reset_user_password/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    temporary_password = f"Temp{secrets.token_hex(4)}!"
    user.set_password(temporary_password)
    db.session.commit()
    flash(f"Temporary password for {user.username}: {temporary_password}", 'success')
    return redirect(url_for('users', page=request.args.get('page', 1, type=int), search=request.args.get('search', '').strip()))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        identity = request.form.get('identity', '').strip()
        if not identity:
            flash('Enter your username or email.', 'danger')
            return render_template('forgot_password.html')

        user = User.query.filter(
            (User.username == identity) | (User.email == identity.lower())
        ).first()

        if user and getattr(user, 'is_approved', True):
            raw_token = create_password_reset_token(user)
            reset_link = url_for('reset_password', token=raw_token, _external=True)
            email_status, email_details = send_password_reset_email(user, reset_link)

            if email_status == 'sent':
                flash('Password reset link sent to your email.', 'success')
            elif app.debug:
                flash(f'Email not sent. Development reset link: {reset_link}', 'warning')
                flash(email_details, 'warning')
            else:
                flash('We could not send the reset email right now. Please contact support or try again later.', 'danger')
        else:
            flash('If the account exists, a reset link has been generated.', 'success')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_record = find_active_password_reset_token(token)
    if not token_record:
        flash('Reset token is invalid or expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html')

        password_issues = validate_password_strength(new_password)
        if password_issues:
            for issue in password_issues:
                flash(issue, 'danger')
            return render_template('reset_password.html')

        token_record.user.set_password(new_password)
        token_record.used_at = datetime.utcnow()
        db.session.commit()
        log_action('reset password', 'user', token_record.user.id)

        flash('Password reset successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if not current_user.check_password(current):
            flash('Current password is incorrect', 'danger')
        elif new != confirm:
            flash('New passwords do not match', 'danger')
        else:
            password_issues = validate_password_strength(new)
            if password_issues:
                for issue in password_issues:
                    flash(issue, 'danger')
                return render_template('change_password.html')

            current_user.set_password(new)
            db.session.commit()
            log_action('changed password', 'user', current_user.id)
            flash('Password changed successfully', 'success')
            return redirect(url_for('dashboard'))

    return render_template('change_password.html')


@app.route('/store-settings', methods=['GET', 'POST'])
@login_required
def store_settings():
    if request.method == 'POST':
        store_name = request.form.get('store_name', '').strip()
        store_description = request.form.get('store_description', '').strip()
        preferred_slug = request.form.get('store_slug', '').strip()
        store_whatsapp = request.form.get('store_whatsapp', '').strip()

        if not store_name:
            flash('Store name is required.', 'danger')
            return render_template('store_settings.html')

        logo_file = request.files.get('store_logo')
        uploaded_logo_url, logo_error = save_uploaded_product_image(logo_file)
        if logo_error:
            flash(logo_error, 'danger')
            return render_template('store_settings.html')

        current_user.store_name = store_name
        current_user.store_description = store_description
        current_user.store_slug = generate_unique_store_slug(preferred_slug or store_name or current_user.username, exclude_user_id=current_user.id)
        current_user.store_whatsapp = store_whatsapp or None
        if uploaded_logo_url:
            current_user.store_logo = uploaded_logo_url
        db.session.commit()
        flash('Store updated successfully.', 'success')
        return redirect(url_for('store_settings'))

    return render_template('store_settings.html')


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'staff').strip().lower()

        if role not in ('admin', 'staff'):
            flash('Invalid role selected.', 'danger')
            return render_template('add_user.html')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('add_user.html')

        password_issues = validate_password_strength(password)
        if password_issues:
            for issue in password_issues:
                flash(issue, 'danger')
            return render_template('add_user.html')

        if User.query.filter_by(username=username).first():
            flash('User exists', 'danger')
            return render_template('add_user.html')

        email = request.form.get('email', '').strip().lower()
        if email and User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return render_template('add_user.html')

        user = User(
            username=username,
            email=email or None,
            role=role,
            store_slug=generate_unique_store_slug(username),
            store_name=username,
            is_approved=True,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_action('created user', 'user', user.id)
        flash('User created', 'success')
        return redirect(url_for('users'))

    return render_template('add_user.html')


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', user.role).strip().lower()
        is_approved = bool(request.form.get('is_approved'))

        if role not in ('admin', 'staff'):
            flash('Invalid role selected.', 'danger')
            return render_template('edit_user.html', user=user)

        existing = User.query.filter(User.username == username, User.id != user.id).first()
        if existing:
            flash('Username already taken.', 'danger')
            return render_template('edit_user.html', user=user)

        existing_email = User.query.filter(User.email == email, User.id != user.id).first() if email else None
        if existing_email:
            flash('Email already taken.', 'danger')
            return render_template('edit_user.html', user=user)

        user.username = username
        user.email = email or None
        user.role = role
        user.is_approved = is_approved
        if not user.store_name:
            user.store_name = username
        if not user.store_slug:
            user.store_slug = generate_unique_store_slug(username, exclude_user_id=user.id)
        if password:
            password_issues = validate_password_strength(password)
            if password_issues:
                for issue in password_issues:
                    flash(issue, 'danger')
                return render_template('edit_user.html', user=user)
            user.set_password(password)

        db.session.commit()
        log_action('edited user', 'user', user.id)
        flash('User updated successfully.', 'success')
        return redirect(url_for('users'))

    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account while logged in.', 'danger')
        return redirect(url_for('users'))

    deleted_user_id = user.id
    db.session.delete(user)
    db.session.commit()
    log_action('deleted user', 'user', deleted_user_id)
    flash('User deleted.', 'success')
    return redirect(url_for('users'))


@app.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    log_action('approved user', 'user', user.id)
    flash(f'User {user.username} approved.', 'success')
    return redirect(url_for('users', page=request.args.get('page', 1, type=int), search=request.args.get('search', '').strip()))


if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        func=check_low_stock,
        trigger='interval',
        minutes=5,
        id='low_stock_checker',
        replace_existing=True,
    )

    # Avoid starting duplicate scheduler workers under Flask debug reloader.
    if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        scheduler.start()

    app.run(host='127.0.0.1', port=5000, debug=True)
