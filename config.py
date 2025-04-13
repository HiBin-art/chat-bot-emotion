# 数据库配置
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '123456',  # 修改为你的MySQL root用户密码
    'database': 'chatbot_db',  # 使用已存在的数据库名
    'port': 3306,
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
    'autocommit': True,
    'connect_timeout': 10,
    'raise_on_warnings': True
}

# 数据库连接池配置
DB_POOL_CONFIG = {
    'pool_name': 'mypool',
    'pool_size': 5,
    'pool_reset_session': True
}

# Flask 配置
FLASK_CONFIG = {
    'SECRET_KEY': 'your_secret_key_here',  # 替换为随机生成的密钥
    'SESSION_TYPE': 'filesystem',
    'PERMANENT_SESSION_LIFETIME': 1800,  # 会话过期时间（秒）
    'SESSION_COOKIE_SECURE': False,  # 开发环境设为 False
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax'
}

# API配置
API_KEY = 'sk-62ac5519d1ad4e36abe7c47c3a43e0bc'
APP_ID = '0283dffc5cbd495cb793347612c3f534'

# 服务器配置
SERVER_CONFIG = {
    'host': '127.0.0.1',  # 修改为本地地址
    'port': 5000,
    'debug': True,
    'threaded': True,
    'use_reloader': True
}

# 如果有 SSL 证书，可以配置 HTTPS
SSL_CONFIG = {
    'enabled': False,  # 是否启用 HTTPS
    'cert': 'path/to/cert.pem',  # SSL 证书路径
    'key': 'path/to/key.pem'  # SSL 密钥路径
}

# 静态文件配置
STATIC_CONFIG = {
    'static_url_path': '/static',
    'static_folder': 'static',
    'template_folder': 'templates'
}

# 安全配置
SECURITY_CONFIG = {
    'SESSION_COOKIE_SECURE': False,  # 开发环境设为 False
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'PERMANENT_SESSION_LIFETIME': 1800,  # 30分钟
    'SECRET_KEY': 'your_secret_key_here'  # 替换为随机密钥
}

# 添加角色配置
CHATBOT_ROLES = {
    'default': {
        'name': '默认助手',
        'app_id': '0283dffc5cbd495cb793347612c3f534',
        'description': '通用型AI助手'
    },
    'emotional': {
        'name': '情感顾问',
        'app_id': 'your_emotional_app_id',  # 替换为实际的情感顾问 APP ID
        'description': '专注于情感咨询的AI助手'
    },
    'professional': {
        'name': '专业顾问',
        'app_id': 'your_professional_app_id',  # 替换为实际的专业顾问 APP ID
        'description': '提供专业建议的AI助手'
    }
}

# 修改 app.py 中的运行配置
if __name__ == '__main__':
    init_app()
    app.run(**SERVER_CONFIG) 