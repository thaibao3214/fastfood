from pymongo import MongoClient
from dotenv import load_dotenv
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Load environment variables
load_dotenv()

try:
    # Connect to MongoDB
    client = MongoClient(os.getenv('MONGO_URI'), serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print("✅ Đã kết nối MongoDB thành công!")

    # Initialize database and collections
    db = client.fastfood
    users_collection = db.users
    monans_collection = db.monans
    transactions_collection = db.transactions
    orders_collection = db.orders
    notifications_collection = db.notifications

    # Định nghĩa cấu trúc địa chỉ giao hàng
    delivery_address_schema = {
        'street': str,      # Số nhà, tên đường
        'district': str,    # Quận/Huyện
        'city': str,        # Thành phố
        'phone': str        # Số điện thoại
    }

    # Định nghĩa cấu trúc đơn hàng
    order_schema = {
        'uid': str,                     # ID người dùng
        'email': str,                   # Email người đặt
        'item_name': str,               # Tên món
        'quantity': int,                # Số lượng
        'price': float,                 # Giá
        'total_amount': float,          # Tổng tiền
        'delivery_type': str,           # Kiểu giao hàng: 'pickup' hoặc 'delivery'
        'delivery_address': dict,       # Thông tin địa chỉ (optional)
        'delivery_fee': float,          # Phí giao hàng (optional)
        'delivery_note': str,           # Ghi chú giao hàng (optional)
        'pickup_time': datetime,        # Thời gian nhận hàng
        'order_time': datetime,         # Thời gian đặt hàng
        'status': str                   # Trạng thái đơn hàng
    }

    def create_order(
        uid: str,
        email: str,
        item_name: str,
        quantity: int,
        price: float,
        delivery_type: str,
        pickup_time: datetime,
        delivery_address: Optional[Dict[str, Any]] = None,
        delivery_note: str = "",
        delivery_fee: float = 0
    ) -> Dict[str, Any]:
        """Tạo đơn hàng mới với thông tin giao hàng tùy chọn"""
        
        # Tính tổng tiền
        total_amount = price * quantity
        if delivery_type == 'delivery':
            total_amount += delivery_fee

        # Tạo đơn hàng cơ bản
        order = {
            'uid': uid,
            'email': email,
            'item_name': item_name,
            'quantity': quantity,
            'price': price,
            'total_amount': total_amount,
            'delivery_type': delivery_type,
            'pickup_time': pickup_time,
            'order_time': datetime.now(timezone.utc),
            'status': 'pending'
        }

        # Thêm thông tin giao hàng nếu có
        if delivery_type == 'delivery':
            if not delivery_address:
                raise ValueError("Thiếu thông tin địa chỉ giao hàng")
            
            # Validate địa chỉ giao hàng
            required_fields = ['street', 'district', 'city', 'phone']
            if not all(field in delivery_address for field in required_fields):
                raise ValueError("Địa chỉ giao hàng không hợp lệ")
            
            order.update({
                'delivery_address': delivery_address,
                'delivery_note': delivery_note,
                'delivery_fee': delivery_fee
            })

        return order

    def get_delivery_fee(district: str) -> float:
        """Tính phí giao hàng dựa trên quận/huyện"""
        fees = {
            'Quận 1': 15000,
            'Quận 2': 20000,
            'Quận 3': 15000,
            'Quận 4': 20000,
            'Quận 5': 15000,
            # Thêm các quận khác
        }
        return fees.get(district, 25000)  # Mặc định 25k cho các quận khác

except Exception as e:
    print(f"❌ Lỗi kết nối MongoDB: {e}")
    raise e