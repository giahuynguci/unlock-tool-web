from flask import Flask, render_template, request, jsonify
from unlock_logic import Config, Utils, ApiClient

# Khởi tạo ứng dụng Flask
app = Flask(__name__)

# Route chính, hiển thị trang giao diện
@app.route('/')
def index():
    """Render trang HTML chính."""
    return render_template('index.html', default_ly_do=Config.DEFAULT_LY_DO)

# Route xử lý yêu cầu mở khóa
@app.route('/unlock', methods=['POST'])
def unlock():
    """Xử lý logic khi người dùng nhấn nút 'Mở khóa'."""
    try:
        # Lấy dữ liệu từ form
        curl_command = request.form.get('curl_command', '')
        user_list_text = request.form.get('user_list', '')
        ly_do = request.form.get('ly_do', Config.DEFAULT_LY_DO)

        # --- Input Validation ---
        if not curl_command or not user_list_text:
            return jsonify({'status': 'error', 'message': 'Vui lòng nhập đủ thông tin cURL và danh sách tài khoản.'}), 400

        # --- Trích xuất thông tin ---
        url, auth, cookies = Utils.parse_curl(curl_command)
        if not auth:
            return jsonify({'status': 'error', 'message': 'Không tìm thấy thông tin Authorization trong cURL. Vui lòng kiểm tra lại.'}), 400

        users_to_unlock = Utils.extract_tokens(user_list_text)
        if not users_to_unlock:
            return jsonify({'status': 'error', 'message': 'Không tìm thấy tài khoản hợp lệ nào trong danh sách.'}), 400

        # --- Gọi API ---
        api_client = ApiClient(auth, cookies)
        # Mặc định URL từ cURL, nếu không có thì dùng URL mặc định
        api_url = url or Config.DEFAULT_URL
        
        status_code, data = api_client.post_unlock(api_url, users_to_unlock, ly_do)

        # --- Trả kết quả ---
        return jsonify({
            'status': 'success',
            'message': f'Gửi yêu cầu thành công tới {api_url}',
            'api_status': status_code,
            'api_response': data,
            'sent_users_count': len(users_to_unlock),
            'sent_users': users_to_unlock
        })

    except Exception as e:
        # Bắt các lỗi không mong muốn
        return jsonify({'status': 'error', 'message': f'Đã có lỗi xảy ra: {str(e)}'}), 500

# Route xử lý yêu cầu chẩn đoán
@app.route('/diagnose', methods=['POST'])
def diagnose():
    """Xử lý logic khi người dùng nhấn nút 'Chẩn đoán'."""
    try:
        # Lấy dữ liệu từ form
        curl_command = request.form.get('curl_command', '')
        user_list_text = request.form.get('user_list', '')
        ly_do = request.form.get('ly_do', Config.DEFAULT_LY_DO)

        # --- Input Validation ---
        if not curl_command or not user_list_text:
            return jsonify({'status': 'error', 'message': 'Vui lòng nhập đủ thông tin cURL và danh sách tài khoản.'}), 400

        # --- Trích xuất thông tin ---
        url, auth, cookies = Utils.parse_curl(curl_command)
        if not auth:
            return jsonify({'status': 'error', 'message': 'Không tìm thấy thông tin Authorization trong cURL.'}), 400

        users_to_diagnose = Utils.extract_tokens(user_list_text)
        if not users_to_diagnose:
            return jsonify({'status': 'error', 'message': 'Không tìm thấy tài khoản hợp lệ nào trong danh sách.'}), 400

        # --- Gọi API Chẩn đoán ---
        api_client = ApiClient(auth, cookies)
        api_url = url or Config.DEFAULT_URL

        not_found_users = api_client.diagnose_not_found(api_url, ly_do, users_to_diagnose)

        # --- Trả kết quả ---
        return jsonify({
            'status': 'success',
            'message': f'Chẩn đoán hoàn tất trên {len(users_to_diagnose)} tài khoản.',
            'tested_count': len(users_to_diagnose),
            'diagnosed_users': users_to_diagnose,
            'not_found_count': len(not_found_users),
            'not_found_users': not_found_users
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Đã có lỗi xảy ra: {str(e)}'}), 500

# Chạy ứng dụng
if __name__ == '__main__':
    # Chạy ở chế độ debug để dễ dàng phát triển
    # Host 0.0.0.0 để có thể truy cập từ các thiết bị khác trong cùng mạng
    app.run(host='0.0.0.0', port=5001, debug=True)

