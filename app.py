from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from firebase_admin import auth
import firebase_config  # Đảm bảo rằng firebase_config khởi tạo firebase_admin
from datetime import datetime
import os
from functools import wraps
from datetime import datetime, timezone, timedelta
from database import users_collection, monans_collection, transactions_collection, orders_collection, notifications_collection,client
from bson import ObjectId
import traceback
from database import get_delivery_fee
from werkzeug.utils import secure_filename  # Add this import

# ...existing imports...

# Add these constants and function below your imports and before routes
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
app = Flask(__name__)
app.secret_key = 'secret123'  # Dùng cho session Flask

# Cấu hình thư mục lưu trữ ảnh
UPLOAD_FOLDER = 'static/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ======= ROUTES =======

# Trang đăng nhập
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

# ✅ Đăng ký người dùng
from datetime import datetime, timezone

@app.route('/verify-token', methods=['POST'])
def verify_token():
    id_token = request.json.get('idToken')
    if not id_token:
        return jsonify({'error': 'Token không được để trống'}), 400

    try:
        # Xác thực token từ Firebase với check_revoked=True và tolerance để xử lý timing
        decoded = auth.verify_id_token(
            id_token, 
            check_revoked=True,
            clock_skew_seconds=60  # Cho phép lệch 1 phút
        )
        
        # Kiểm tra thời gian hết hạn của token
        exp = decoded.get('exp', 0)
        now = datetime.now(timezone.utc).timestamp()
        if exp < now:
            return jsonify({'error': 'Token đã hết hạn'}), 401

        session['uid'] = decoded['uid']

        # Lấy thông tin user từ MongoDB
        user = users_collection.find_one({'uid': decoded['uid']})
        
        # Nếu user chưa có trong MongoDB, tạo mới từ Firebase
        if not user:
            try:
                firebase_user = auth.get_user(decoded['uid'])
                new_user = {
                    'uid': decoded['uid'],
                    'email': firebase_user.email,
                    'created_at': datetime.now(timezone.utc),
                    'role': 'user',
                    'last_login': datetime.now(timezone.utc),
                    'is_active': True,
                    'balance': 0,
                    'failed_login_attempts': 0,
                    'last_failed_login': None,
                    'login_history': [],
                    'device_info': request.headers.get('User-Agent')
                }
                users_collection.insert_one(new_user)
                user = new_user
                print(f"✅ Đã tạo user mới trong MongoDB: {new_user['email']}")
            except Exception as e:
                print(f"❌ Lỗi khi tạo user mới: {str(e)}")
                return jsonify({'error': 'Lỗi khi tạo tài khoản mới'}), 500
        else:
            # Kiểm tra trạng thái tài khoản
            if not user.get('is_active', True):
                return jsonify({'error': 'Tài khoản đã bị khóa'}), 401

            # Kiểm tra số lần đăng nhập thất bại
            if user.get('failed_login_attempts', 0) >= 5:
                last_failed = user.get('last_failed_login')
                if last_failed and (now - last_failed.timestamp()) < 1800:  # 30 phút
                    return jsonify({
                        'error': 'Tài khoản tạm thời bị khóa do đăng nhập sai nhiều lần'
                    }), 401

            # Reset số lần đăng nhập thất bại khi đăng nhập thành công
            current_login = {
                'timestamp': datetime.now(timezone.utc),
                'device': request.headers.get('User-Agent'),
                'ip': request.remote_addr
            }

            # Cập nhật thông tin đăng nhập
            users_collection.update_one(
                {'uid': decoded['uid']},
                {
                    '$set': {
                        'last_login': datetime.now(timezone.utc),
                        'failed_login_attempts': 0,
                        'last_failed_login': None,
                        'device_info': request.headers.get('User-Agent')
                    },
                    '$push': {
                        'login_history': {
                            '$each': [current_login],
                            '$slice': -10  # Giữ 10 lần đăng nhập gần nhất
                        }
                    }
                }
            )

        # Lưu thông tin vào session
        session['role'] = user.get('role', 'user')
        session['email'] = user.get('email')
        session['last_login'] = user.get('last_login')
        session['is_active'] = user.get('is_active', True)
        session['balance'] = user.get('balance', 0)

        return jsonify({
            'message': 'Xác thực thành công',
            'role': session['role'],
            'email': user['email'],
            'last_login': user.get('last_login'),
            'is_active': user.get('is_active', True),
            'balance': user.get('balance', 0)
        })

    except auth.InvalidIdTokenError as e:
        error_msg = str(e)
        # Tăng số lần đăng nhập thất bại
        if 'uid' in session:
            users_collection.update_one(
                {'uid': session['uid']},
                {
                    '$inc': {'failed_login_attempts': 1},
                    '$set': {'last_failed_login': datetime.now(timezone.utc)}
                }
            )
            
        if 'Token used too early' in error_msg:
            return jsonify({
                'error': 'Vui lòng kiểm tra lại thời gian máy tính của bạn'
            }), 401
        elif 'Token has expired' in error_msg:
            return jsonify({'error': 'Phiên đăng nhập đã hết hạn'}), 401
        return jsonify({'error': 'Token không hợp lệ'}), 401
        
    except auth.ExpiredIdTokenError:
        return jsonify({'error': 'Token đã hết hạn, vui lòng đăng nhập lại'}), 401
        
    except auth.RevokedIdTokenError:
        return jsonify({'error': 'Token đã bị thu hồi, vui lòng đăng nhập lại'}), 401
        
    except Exception as e:
        print(f"❌ Lỗi xác thực không xác định: {str(e)}")
        return jsonify({'error': 'Có lỗi xảy ra khi xác thực'}), 401
# ✅ Xác thực Firebase → lưu session
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        id_token = data.get('idToken')

        if not email or not id_token:
            return jsonify({'error': 'Thiếu thông tin đăng ký'}), 400

        # Xác thực token từ Firebase
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']

        # Kiểm tra xem user đã tồn tại trong MongoDB chưa
        existing_user = users_collection.find_one({'uid': uid})
        if existing_user:
            return jsonify({'error': 'Tài khoản đã tồn tại'}), 400

        # Tạo user mới trong MongoDB
        new_user = {
            'uid': uid,
            'email': email,
            'created_at': datetime.now(timezone.utc),
            'role': 'user',
            'is_active': True,
            'balance': 0,
            'failed_login_attempts': 0,
            'last_failed_login': None,
            'login_history': []
        }

        users_collection.insert_one(new_user)
        return jsonify({'message': 'Đăng ký thành công'})

    except Exception as e:
        print(f"❌ Lỗi đăng ký: {str(e)}")
        return jsonify({'error': str(e)}), 400
# ✅ Quyền admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'uid' not in session:
            return redirect(url_for('login'))
        
        user = users_collection.find_one({'uid': session['uid']})
        if not user or user.get('role') != 'admin':
            return jsonify({'error': 'Không có quyền truy cập'}), 403
            
        return f(*args, **kwargs)
    return decorated_function
# ✅ Trang menu nhóm (cơm, mỳ, nước...)
@app.route('/menu')
def menu():
    try:
        # Danh sách cố định các loại món ăn
        menu_groups = [
            {
                'id': 'com',
                'name': 'Menu Cơm',
                'icon': '🍚'  # Icon cơm
            },
            {
                'id': 'my', 
                'name': 'Menu Mỳ',
                'icon': '🍜'  # Icon mỳ
            },
            {
                'id': 'nuoc',
                'name': 'Menu Nước',
                'icon': '🥤'  # Icon nước
            },
            {
                'id': 'khac',
                'name': 'Món khác',
                'icon': '🍴'  # Icon món khác
            }
        ]
        
        return render_template('menu_groups.html', menu_groups=menu_groups)
        
    except Exception as e:
        print("❌ Lỗi khi lấy danh mục món ăn:", str(e))
        return jsonify({'error': str(e)}), 500
# ✅ Trang hiển thị món ăn theo nhóm
@app.route('/menu/<loai>')
def monan_theo_loai(loai):
    try:
        items = list(monans_collection.find({'loai': loai}))
        for item in items:
            item['_id'] = str(item['_id'])
            item['gia'] = float(item['gia'])
        
        # Use UTC time for consistency
        now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M')
        user = None
        if 'uid' in session:
            user = users_collection.find_one({'uid': session['uid']})
            
        return render_template('menu_list.html', menu=items, now=now, user=user)
        
    except Exception as e:
        print("❌ Lỗi khi lấy danh sách món ăn:", str(e))
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
# ✅ Thêm món ăn mới
@app.route('/add_item', methods=['GET', 'POST'])
@admin_required
def add_item():
    if request.method == 'POST':
        try:
            # Lấy thông tin từ form
            ten = request.form['ten']
            gia = float(request.form['gia'])
            moTa = request.form['moTa']
            loai = request.form['loai']
            
            # Xử lý file hình ảnh
            hinh = request.files['hinhAnh']
            if hinh:
                # Tạo tên file độc nhất
                filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hinh.filename}"
                # Lưu file vào thư mục static/images
                hinh.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Đường dẫn để lưu vào MongoDB
                hinhAnh = f"images/{filename}"
            
            # Tạo document để lưu vào MongoDB
            monan_moi = {
                'ten': ten,
                'gia': gia,
                'moTa': moTa,
                'loai': loai,
                'hinhAnh': hinhAnh,
                'ngayTao': datetime.utcnow()
            }
            
            # Lưu vào MongoDB
            result = monans_collection.insert_one(monan_moi)
            
            # In log để debug
            print(f"✅ Đã thêm món ăn mới với ID: {result.inserted_id}")
            
            return redirect(url_for('menu'))
            
        except Exception as e:
            print(f"❌ Lỗi khi thêm món ăn: {e}")
            return jsonify({'error': str(e)}), 500
            
    return render_template('add_item.html')
# ✅ Đăng xuất
@app.route('/logout')
def logout():
    session.clear()  # Xóa session khi đăng xuất
    return redirect(url_for('login'))
# ✅ Quản lý user
@app.route('/admin/users')
@admin_required
def manage_users():
    users = list(users_collection.find({}, {'_id': 0, 'password': 0}))
    return render_template('admin/users.html', users=users)

@app.route('/admin/update_role/<uid>', methods=['POST'])
@admin_required
def update_role(uid):  # Add uid parameter here
    new_role = request.form['role']
    users_collection.update_one(
        {'uid': uid},
        {'$set': {'role': new_role}}
    )
    return jsonify({'message': 'Cập nhật quyền thành công'})
@app.context_processor
def utility_processor():
    def get_user():
        if 'uid' in session:
            return users_collection.find_one({'uid': session['uid']})
        return None
    return dict(get_user=get_user)
# ✅ Trang thông tin cá nhân
@app.route('/profile')
def profile():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'uid': session['uid']})
    if not user:
        return redirect(url_for('login'))
        
    return render_template('profile.html', user=user)

# ✅ Đổi mật khẩu
@app.route('/change-password', methods=['POST'])
def change_password():
    if 'uid' not in session:
        return jsonify({'error': 'Chưa đăng nhập'}), 401
    
    try:
        data = request.json
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        
        # Lấy user từ Firebase
        user = auth.get_user(session['uid'])
        
        # Cập nhật mật khẩu
        auth.update_user(
            session['uid'],
            password=new_password
        )
        
        return jsonify({'message': 'Đổi mật khẩu thành công'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400
@app.route('/deposit', methods=['POST'])
def deposit():
    if 'uid' not in session:
        return jsonify({'error': 'Chưa đăng nhập'}), 401
    
    try:
        amount = float(request.json.get('amount', 0))
        if amount <= 0:
            return jsonify({'error': 'Số tiền không hợp lệ'}), 400

        # Cập nhật số dư
        result = users_collection.update_one(
            {'uid': session['uid']},
            {'$inc': {'balance': amount}}
        )
        
        # Lưu lịch sử giao dịch
        transaction = {
            'uid': session['uid'],
            'type': 'deposit',
            'amount': amount,
            'timestamp': datetime.now(timezone.utc),
            'status': 'success'
        }
        transactions_collection.insert_one(transaction)

        return jsonify({'message': f'Đã nạp {amount:,.0f}đ vào tài khoản'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/transactions')
def transaction_history():
    if 'uid' not in session:
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'uid': session['uid']})
    if not user:
        return redirect(url_for('login'))
    
    transactions = list(transactions_collection.find(
        {'uid': session['uid']},
        {'_id': 0}
    ).sort('timestamp', -1))
    
    return render_template('transactions.html', transactions=transactions, user=user)
# Thêm routes mới sau route manage_users
@app.route('/admin/toggle_user/<uid>', methods=['POST'])
@admin_required
def toggle_user(uid):
    try:
        # Không cho phép admin tự khóa tài khoản của mình
        if uid == session['uid']:
            return jsonify({'error': 'Không thể khóa tài khoản của chính mình'}), 400
            
        user = users_collection.find_one({'uid': uid})
        new_status = not user.get('is_active', True)
        
        # Cập nhật trạng thái trong MongoDB
        users_collection.update_one(
            {'uid': uid},
            {'$set': {'is_active': new_status}}
        )
        
        # Disable/Enable user trong Firebase
        if new_status:
            auth.update_user(uid, disabled=False)
        else:
            auth.update_user(uid, disabled=True)
            
        return jsonify({
            'message': f'Đã {"mở khóa" if new_status else "khóa"} tài khoản thành công'
        })
    except Exception as e:
        print(f"❌ Lỗi khi thay đổi trạng thái user: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/admin/delete_user/<uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    try:
        # Không cho phép admin tự xóa tài khoản của mình
        if uid == session['uid']:
            return jsonify({'error': 'Không thể xóa tài khoản của chính mình'}), 400
            
        # Xóa user trong Firebase
        auth.delete_user(uid)
        
        # Xóa user trong MongoDB
        users_collection.delete_one({'uid': uid})
        
        # Xóa lịch sử giao dịch của user
        transactions_collection.delete_many({'uid': uid})
        
        return jsonify({'message': 'Đã xóa tài khoản thành công'})
    except Exception as e:
        print(f"❌ Lỗi khi xóa user: {e}")
        return jsonify({'error': str(e)}), 400
@app.route('/place-order', methods=['POST'])
def place_order():
    # Kiểm tra đăng nhập
    if 'uid' not in session:
        return jsonify({'error': 'Vui lòng đăng nhập để đặt hàng'}), 401

    try:
        data = request.json
        user = users_collection.find_one({'uid': session['uid']})
        
        if not user:
            return jsonify({'error': 'Không tìm thấy thông tin người dùng'}), 400

        # Kiểm tra dữ liệu đầu vào cơ bản
        required_fields = ['itemName', 'quantity', 'price', 'pickupTime', 'delivery_type']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Thiếu thông tin đặt hàng'}), 400

        # Kiểm tra thông tin giao hàng nếu là delivery
        delivery_fee = 0
        if data['delivery_type'] == 'delivery':
            if not data.get('address') or not all(
                key in data['address'] for key in ['street', 'district', 'city', 'phone']
            ):
                return jsonify({'error': 'Thiếu thông tin địa chỉ giao hàng'}), 400
            
            # Validate số điện thoại
            phone = data['address']['phone']
            if not phone.isdigit() or len(phone) < 10:
                return jsonify({'error': 'Số điện thoại không hợp lệ'}), 400
                
            # Tính phí giao hàng
            delivery_fee = get_delivery_fee(data['address']['district'])

        # Validate số lượng
        try:
            quantity = int(data['quantity'])
            if quantity < 1 or quantity > 10:  # Giới hạn tối đa 10 món
                return jsonify({'error': 'Số lượng phải từ 1 đến 10'}), 400
        except ValueError:
            return jsonify({'error': 'Số lượng không hợp lệ'}), 400

        # Kiểm tra món ăn và giá
        menu_item = monans_collection.find_one({'ten': data['itemName']})
        if not menu_item:
            return jsonify({'error': 'Món ăn không tồn tại'}), 400

        if abs(float(menu_item['gia']) - float(data['price'])) > 0.01:
            return jsonify({'error': 'Giá không hợp lệ'}), 400

        # Tính tổng tiền bao gồm phí giao hàng
        total_amount = float(menu_item['gia']) * quantity + delivery_fee

        # Kiểm tra số dư
        if user['balance'] < total_amount:
            return jsonify({
                'error': f'Số dư không đủ. Cần: {total_amount:,.0f}đ (bao gồm phí giao {delivery_fee:,.0f}đ) - Hiện có: {user["balance"]:,.0f}đ'
            }), 400

        # Xử lý thời gian đặt/giao hàng
        try:
            pickup_time = datetime.fromisoformat(data['pickupTime'].replace('Z', '+00:00'))
            if not pickup_time.tzinfo:
                pickup_time = pickup_time.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            min_time = now + timedelta(minutes=30)
            max_time = now + timedelta(days=7)

            if pickup_time < min_time:
                return jsonify({
                    'error': 'Thời gian nhận hàng phải sau thời điểm hiện tại ít nhất 30 phút'
                }), 400

            if pickup_time > max_time:
                return jsonify({
                    'error': 'Không thể đặt hàng trước quá 7 ngày'
                }), 400

        except ValueError:
            return jsonify({'error': 'Định dạng thời gian không hợp lệ'}), 400

        # Tạo đơn hàng mới
        order = {
            'uid': session['uid'],
            'email': user['email'],
            'item_name': menu_item['ten'],
            'quantity': quantity,
            'price': float(menu_item['gia']),
            'total_amount': total_amount,
            'delivery_type': data['delivery_type'],
            'pickup_time': pickup_time,
            'order_time': now,
            'status': 'pending',
            'note': data.get('note', '').strip(),
        }

        # Thêm thông tin giao hàng nếu có
        if data['delivery_type'] == 'delivery':
            order.update({
                'delivery_address': {
                    'street': data['address']['street'],
                    'district': data['address']['district'],
                    'city': data['address']['city'],
                    'phone': data['address']['phone']
                },
                'delivery_fee': delivery_fee,
                'delivery_note': data.get('delivery_note', '')
            })

        # Sử dụng MongoDB transaction
        with client.start_session() as mongo_session:
            with mongo_session.start_transaction():
                # Lưu đơn hàng
                result = orders_collection.insert_one(order, session=mongo_session)

                # Trừ tiền từ tài khoản
                update_result = users_collection.update_one(
                    {
                        'uid': session['uid'],
                        'balance': {'$gte': total_amount}
                    },
                    {'$inc': {'balance': -total_amount}},
                    session=mongo_session
                )

                if update_result.modified_count == 0:
                    raise Exception('Số dư không đủ hoặc có lỗi khi trừ tiền')

                # Lưu lịch sử giao dịch
                delivery_info = (
                    f"(Giao hàng đến: {data['address']['district']})" 
                    if data['delivery_type'] == 'delivery' 
                    else "(Tự đến lấy)"
                )
                
                transaction = {
                    'uid': session['uid'],
                    'type': 'payment',
                    'amount': -total_amount,
                    'order_id': str(result.inserted_id),
                    'timestamp': now,
                    'status': 'success',
                    'description': (
                        f'Đặt món {menu_item["ten"]} x{quantity} '
                        f'{"+ Phí giao: {:,.0f}đ ".format(delivery_fee) if delivery_fee else ""}'
                        f'(Nhận: {pickup_time.strftime("%H:%M %d/%m/%Y")}) {delivery_info}'
                    )
                }
                transactions_collection.insert_one(transaction, session=mongo_session)

                # Tạo thông báo cho admin
                notification = {
                    'type': 'new_order',
                    'order_id': str(result.inserted_id),
                    'message': f'Đơn hàng mới từ {user["email"]}: {menu_item["ten"]} x{quantity}',
                    'created_at': now,
                    'is_read': False,
                    'details': {
                        'item_name': menu_item['ten'],
                        'quantity': quantity,
                        'total_amount': total_amount,
                        'pickup_time': pickup_time,
                        'user_email': user['email'],
                        'note': data.get('note', '').strip(),
                        'delivery_type': data['delivery_type'],
                        'delivery_fee': delivery_fee if data['delivery_type'] == 'delivery' else 0,
                        'delivery_address': data['address'] if data['delivery_type'] == 'delivery' else None,
                        'delivery_note': data.get('delivery_note', '') if data['delivery_type'] == 'delivery' else ''
                    }
                }
                notifications_collection.insert_one(notification, session=mongo_session)

        # Trả về kết quả thành công
        response = {
            'message': 'Đặt hàng thành công',
            'orderId': str(result.inserted_id),
            'pickup_time': pickup_time.strftime('%H:%M %d/%m/%Y'),
            'remaining_balance': user['balance'] - total_amount,
            'item': {
                'name': menu_item['ten'],
                'quantity': quantity,
                'total': total_amount
            }
        }

        # Thêm thông tin giao hàng vào response
        if data['delivery_type'] == 'delivery':
            response['delivery'] = {
                'fee': delivery_fee,
                'address': data['address'],
                'note': data.get('delivery_note', '')
            }

        return jsonify(response)

    except Exception as e:
        print(f"❌ Lỗi khi đặt hàng: {str(e)}")
        print(traceback.format_exc())
        return jsonify({
            'error': 'Có lỗi xảy ra khi đặt hàng. Vui lòng thử lại sau.',
            'details': str(e) if app.debug else None
        }), 400
@app.route('/admin/notifications')
@admin_required
def admin_notifications():
    notifications = list(notifications_collection.find().sort('created_at', -1))
    for notification in notifications:
        notification['_id'] = str(notification['_id'])
    return render_template('admin/notifications.html', notifications=notifications)

@app.route('/admin/notifications/mark-read/<notification_id>', methods=['POST'])
@admin_required
def mark_notification_read(notification_id):
    try:
        notifications_collection.update_one(
            {'_id': ObjectId(notification_id)},
            {'$set': {'is_read': True}}
        )
        return jsonify({'message': 'Đã đánh dấu đã đọc'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/admin/notifications/unread-count')
@admin_required
def get_unread_count():
    count = notifications_collection.count_documents({'is_read': False})
    return jsonify({'count': count})
@app.route('/admin/delete-item/<item_id>', methods=['DELETE'])
@app.route('/admin/delete-item/<item_id>', methods=['DELETE'])
def delete_item(item_id):
    try:
        # Lấy thông tin món từ database
        menu_item = monans_collection.find_one({'_id': ObjectId(item_id)})
        if not menu_item:
            return jsonify({'error': 'Không tìm thấy món này'}), 404

        # Xóa hình ảnh cũ nếu có
        if menu_item.get('hinhAnh'):
            # Extract filename from path
            filename = menu_item['hinhAnh'].split('/')[-1]
            old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(old_image_path):
                os.remove(old_image_path)

        # Xóa món từ database
        monans_collection.delete_one({'_id': ObjectId(item_id)})

        return jsonify({
            'message': 'Xóa món thành công',
            'deleted_id': str(item_id)
        })

    except Exception as e:
        print(f"❌ Lỗi khi xóa món: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/edit-item/<item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    try:
        # Get the item from database
        item = monans_collection.find_one({'_id': ObjectId(item_id)})
        if not item:
            flash('Không tìm thấy món này', 'error')
            return redirect(url_for('menu'))

        if request.method == 'POST':
            ten = request.form['ten']
            gia = int(request.form['gia'])
            moTa = request.form['moTa']
            hinhAnh = item['hinhAnh']  # Keep existing image by default

            # Check if new image was uploaded
            if 'hinhAnh' in request.files and request.files['hinhAnh'].filename:
                file = request.files['hinhAnh']
                if file and allowed_file(file.filename):
                    # Delete old image
                    if item['hinhAnh']:
                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], item['hinhAnh'].split('/')[-1])
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                    
                    # Save new image
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    hinhAnh = filename

            # Update in database
            monans_collection.update_one(
                {'_id': ObjectId(item_id)},
                {
                    '$set': {
                        'ten': ten,
                        'gia': gia,
                        'moTa': moTa,
                        'hinhAnh': hinhAnh
                    }
                }
            )

            flash('Cập nhật món thành công!', 'success')
            return redirect(url_for('menu'))

        return render_template('edit_item.html', item=item)

    except Exception as e:
        print(f"❌ Lỗi khi sửa món: {str(e)}")
        flash(str(e), 'error')
        return redirect(url_for('menu'))
# ======= MAIN =======

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
