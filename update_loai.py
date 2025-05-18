from database import menu_collection

# Danh sách cập nhật theo tên món ăn
updates = {
    "Cơm gà xối mỡ": "com",
    "Cơm tấm sườn": "com",
    "Phở bò tái": "my",
    "Bún bò Huế": "my",
    "Trà sữa": "nuoc",
    "Nước suối": "nuoc",
    "Cá viên chiên": "khac"
}

for ten, loai in updates.items():
    result = menu_collection.update_one(
        {"ten": ten},
        {"$set": {"loai": loai}}
    )
    print(f"✅ {ten} → {loai} (matched: {result.matched_count})")
