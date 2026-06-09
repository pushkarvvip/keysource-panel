users:
  id, username, password_hash, balance (integer), is_admin (0/1), is_owner (0/1), created_at

keys:
  id, key_code (unique random string), created_by (admin/owner user_id), balance_amount, device_limit (default 1), expiry_days (null = unlimited), created_at, is_used (0/1), used_by_user_id (nullable), used_device_id (nullable), used_at

devices:
  id, user_id, device_id (unique per user per device), last_login
