import time
import traceback
import json
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from config import DB_CONFIG, DB_POOL_CONFIG

class DatabaseManager:
    def __init__(self):
        try:
            # 直接连接到已存在的数据库
            config = {**DB_CONFIG, **DB_POOL_CONFIG}  # 合并配置
            config['autocommit'] = True  # 自动提交
            config['get_warnings'] = True  # 获取警告
            config['raise_on_warnings'] = True  # 警告时抛出异常
            config['consume_results'] = True  # 自动消费结果
            config['pool_size'] = 5  # 连接池大小
            config['pool_name'] = 'mypool'  # 连接池名称
            config['pool_reset_session'] = True  # 重置会话
            
            # 尝试直接连接数据库
            try:
                self.connection = mysql.connector.connect(**config)
            except mysql.connector.Error as e:
                if e.errno == mysql.connector.errorcode.ER_BAD_DB_ERROR:
                    # 数据库不存在，创建它
                    self._create_database()
                    # 重新尝试连接
                    self.connection = mysql.connector.connect(**config)
                else:
                    raise
            
            # 重试机制
            max_retries = 3
            retry_count = 0
            last_error = None
            
            self.cursor = self.connection.cursor(dictionary=True, buffered=True)
            
            # 设置连接超时和自动重连
            self.connection.ping(True)
            self.connection.autocommit = True
            
            # 检查表是否需要创建或更新
            self._check_tables()
            
        except Exception as e:
            print(f"数据库初始化失败: {e}")
            traceback.print_exc()
            raise
    
    def _check_tables(self):
        """检查并创建或更新必要的表"""
        try:
            # 检查每个表是否存在
            tables = [
                'users', 'chat_sessions', 'chat_history', 
                'announcements', 'announcement_reads',
                'surveys', 'survey_questions', 'survey_responses', 
                'survey_answers', 'chatbot_roles'  # 添加 chatbot_roles 到检查列表
            ]
            
            missing_tables = []
            for table in tables:
                self.cursor.execute(f"SHOW TABLES LIKE '{table}'")
                if not self.cursor.fetchone():
                    print(f"表 {table} 不存在")
                    missing_tables.append(table)
            
            if missing_tables:
                print(f"以下表不存在，开始创建: {', '.join(missing_tables)}")
                self._create_missing_tables(missing_tables)
            
            # 创建默认管理员账户（如果不存在）
            self._create_default_admin()
            
            # 确保创建默认角色
            self._create_default_roles()
            
        except Exception as e:
            print(f"检查表结构失败: {e}")
            traceback.print_exc()
            raise

    def _create_missing_tables(self, missing_tables):
        """只创建缺失的表"""
        print(f"开始创建缺失的表: {missing_tables}")
        try:
            # 表创建SQL语句映射
            table_creation_sql = {
                'users': '''
                    CREATE TABLE users (
                        user_id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE,
                        password_hash VARCHAR(255),
                        email VARCHAR(100) UNIQUE,
                        role ENUM('admin', 'user') DEFAULT 'user',
                        status ENUM('active', 'disabled') DEFAULT 'active',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''',
                'chatbot_roles': '''
                    CREATE TABLE chatbot_roles (
                        role_id VARCHAR(50) PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        app_id VARCHAR(100) NOT NULL,
                        description TEXT,
                        is_default BOOLEAN DEFAULT FALSE,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        created_by INT,
                        FOREIGN KEY (created_by) REFERENCES users(user_id)
                    )
                ''',
                # ... 其他表的创建语句 ...
            }
            
            # 按照依赖关系排序表
            table_order = [
                'users',
                'chatbot_roles',
                'chat_sessions',
                'chat_history',
                'announcements',
                'announcement_reads',
                'surveys',
                'survey_questions',
                'survey_responses',
                'survey_answers'
            ]
            
            # 按顺序创建缺失的表
            for table in table_order:
                if table in missing_tables:
                    print(f"创建表 {table}...")
                    self.cursor.execute(table_creation_sql[table])
                    print(f"表 {table} 创建成功")
            
            self.connection.commit()
            print("所有缺失的表创建完成")
            
        except Exception as e:
            print(f"创建表失败: {e}")
            self.connection.rollback()
            raise
    
    def _create_database(self):
        """创建数据库（如果不存在）"""
        try:
            # 创建临时连接（不指定数据库）
            temp_config = DB_CONFIG.copy()
            temp_config.pop('database', None)  # 安全地移除数据库名
            conn = mysql.connector.connect(**temp_config)
            cursor = conn.cursor()
            
            # 创建数据库
            database_name = DB_CONFIG['database']
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name}")
            
            # 确保创建成功后选择该数据库
            cursor.execute(f"USE {database_name}")
            
            cursor.close()
            conn.close()
            print(f"数据库 {database_name} 创建成功或已存在")
        except Exception as e:
            if e.errno == mysql.connector.errorcode.ER_DB_CREATE_EXISTS:
                print(f"数据库 {DB_CONFIG['database']} 已存在，继续执行")
            else:
                print(f"创建数据库失败: {e}")
                raise
    
    def _create_tables(self):
        print("开始创建或更新数据库表...")
        try:
            # 创建用户表
            print("创建用户表...")
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE,
                    password_hash VARCHAR(255),
                    email VARCHAR(100) UNIQUE,
                    role ENUM('admin', 'user') DEFAULT 'user',
                    status ENUM('active', 'disabled') DEFAULT 'active',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建角色表
            print("创建角色表...")
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS chatbot_roles (
                    role_id VARCHAR(50) PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    app_id VARCHAR(100) NOT NULL,
                    description TEXT,
                    is_default BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    created_by INT,
                    FOREIGN KEY (created_by) REFERENCES users(user_id)
                )
            ''')
            
            # 创建会话表
            print("创建会话表...")
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS chat_sessions (
                    session_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    session_name VARCHAR(100),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            # 创建对话历史表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS chat_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    session_id INT,
                    message TEXT,
                    response TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id),
                    FOREIGN KEY (session_id) REFERENCES chat_sessions(session_id)
                )
            ''')
            
            # 创建公告表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS announcements (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(200) NOT NULL,
                    content TEXT NOT NULL,
                    status ENUM('draft', 'published', 'archived') DEFAULT 'draft',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    created_by INT,
                    FOREIGN KEY (created_by) REFERENCES users(user_id)
                )
            ''')
            
            # 创建公告阅读记录表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS announcement_reads (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    announcement_id INT,
                    user_id INT,
                    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (announcement_id) REFERENCES announcements(id),
                    FOREIGN KEY (user_id) REFERENCES users(user_id),
                    UNIQUE KEY unique_read (announcement_id, user_id)
                )
            ''')
            
            # 创建问卷表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS surveys (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(200) NOT NULL,
                    description TEXT,
                    status ENUM('draft', 'published', 'closed') DEFAULT 'draft',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    created_by INT,
                    FOREIGN KEY (created_by) REFERENCES users(user_id)
                )
            ''')
            
            # 创建问题表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS survey_questions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    survey_id INT,
                    question_text TEXT NOT NULL,
                    question_type ENUM('single_choice', 'multiple_choice', 'text') NOT NULL,
                    options JSON,
                    required BOOLEAN DEFAULT TRUE,
                    order_num INT,
                    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
                )
            ''')
            
            # 创建答卷表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS survey_responses (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    survey_id INT,
                    user_id INT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            # 创建答案表
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS survey_answers (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    response_id INT,
                    question_id INT,
                    answer_text TEXT,
                    answer_options JSON,
                    FOREIGN KEY (response_id) REFERENCES survey_responses(id) ON DELETE CASCADE,
                    FOREIGN KEY (question_id) REFERENCES survey_questions(id)
                )
            ''')
            
            self.connection.commit()
            print("所有表创建完成")
            
            # 确保表创建后立即创建默认数据
            print("开始创建默认数据...")
            self._create_default_admin()
            self._create_default_roles()
            print("默认数据创建完成")
            
        except Exception as e:
            print(f"创建表失败: {e}")
            self.connection.rollback()
            raise
    
    def _create_default_admin(self):
        """创建默认管理员和测试用户账户"""
        try:
            # 检查管理员账户是否已存在
            admin_exists = self._execute_query(
                "SELECT user_id FROM users WHERE username = 'admin'",
                fetch=True
            )
            
            # 检查测试用户是否已存在
            test_user_exists = self._execute_query(
                "SELECT user_id FROM users WHERE username = 'test_user'",
                fetch=True
            )
            
            # 创建管理员账户
            if not admin_exists:
                admin_query = '''
                    INSERT INTO users (username, password_hash, email, role)
                    VALUES (%s, %s, %s, %s)
                '''
                admin_password = generate_password_hash('admin123')
                self._execute_query(admin_query, ('admin', admin_password, 'admin@example.com', 'admin'))
                print("成功创建管理员账户")
            else:
                print("管理员账户已存在")
            
            # 创建测试用户账户
            if not test_user_exists:
                user_query = '''
                    INSERT INTO users (username, password_hash, email, role)
                    VALUES (%s, %s, %s, %s)
                '''
                user_password = generate_password_hash('user123')
                self._execute_query(user_query, ('test_user', user_password, 'user@example.com', 'user'))
                print("成功创建测试用户账户")
            else:
                print("测试用户账户已存在")
            
            # 提交事务
            self.connection.commit()
            
        except Exception as e:
            print(f"创建默认账户失败: {e}")
            self.connection.rollback()
    
    def register_user(self, username, password, email):
        try:
            query = '''
                INSERT INTO users (username, password_hash, email)
                VALUES (%s, %s, %s)
            '''
            password_hash = generate_password_hash(password)
            self.cursor.execute(query, (username, password_hash, email))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"注册用户失败: {e}")
            return False
    
    def verify_user(self, username, password):
        """验证用户登录"""
        try:
            query = "SELECT * FROM users WHERE username = %s"
            result = self._execute_query(query, (username,), fetch=True)
            if result and check_password_hash(result[0]['password_hash'], password):
                return result[0]
            return None
        except Exception as e:
            print(f"验证用户失败: {e}")
            return None
    
    def save_chat_history(self, user_id, session_id, message, response):
        """保存聊天历史"""
        try:
            # 确保会话存在
            session_check = self._execute_query(
                "SELECT session_id FROM chat_sessions WHERE session_id = %s AND user_id = %s",
                (session_id, user_id),
                fetch=True
            )
            
            if not session_check:
                # 如果会话不存在，创建新会话
                query = '''
                    INSERT INTO chat_sessions (session_id, user_id, session_name)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE session_id = session_id
                '''
                session_name = f"对话 {self._get_session_count(user_id) + 1}"
                if not self._execute_query(query, (session_id, user_id, session_name)):
                    raise Exception("创建会话失败")
            
            # 保存聊天记录
            query = '''
                INSERT INTO chat_history (user_id, session_id, message, response)
                VALUES (%s, %s, %s, %s)
            '''
            if not self._execute_query(query, (user_id, session_id, message, response)):
                raise Exception("保存聊天记录失败")
            
            return True
            
        except Exception as e:
            print(f"保存聊天历史失败: {e}")
            return False
    
    def get_chat_history(self, user_id, session_id):
        """获取聊天历史"""
        try:
            query = '''
                SELECT message, response FROM chat_history 
                WHERE user_id = %s AND session_id = %s 
                ORDER BY timestamp ASC
            '''
            return self._execute_query(query, (user_id, session_id), fetch=True) or []
        except Exception as e:
            print(f"获取聊天历史失败: {e}")
            return []
    
    def create_chat_session(self, user_id, session_name=None):
        """创建新的会话"""
        try:
            if not session_name:
                # 获取当前会话数量
                count = self._get_session_count(user_id)
                session_name = f"对话 {count + 1}"
            
            query = '''
                INSERT INTO chat_sessions (user_id, session_name)
                VALUES (%s, %s)
            '''
            if not self._execute_query(query, (user_id, session_name)):
                raise Exception("创建会话失败")
            
            # 获取新创建的会话ID
            result = self._execute_query(
                "SELECT LAST_INSERT_ID() as id",
                fetch=True
            )
            if result and result[0]:
                return result[0]['id']
            return None
            
        except Exception as e:
            print(f"创建会话失败: {e}")
            return None
    
    def get_user_sessions(self, user_id):
        """获取用户的所有会话"""
        try:
            query = '''
                SELECT cs.*, 
                    (SELECT COUNT(*) FROM chat_history ch WHERE ch.session_id = cs.session_id) as message_count,
                    (SELECT MAX(timestamp) FROM chat_history ch WHERE ch.session_id = cs.session_id) as last_message_time
                FROM chat_sessions cs
                WHERE cs.user_id = %s
                ORDER BY last_message_time DESC
            '''
            return self._execute_query(query, (user_id,), fetch=True) or []
        except Exception as e:
            print(f"获取用户会话失败: {e}")
            return []
    
    def _get_session_count(self, user_id):
        """获取用户当前的会话数量"""
        try:
            result = self._execute_query(
                "SELECT COUNT(*) as count FROM chat_sessions WHERE user_id = %s",
                (user_id,),
                fetch=True
            )
            return result[0]['count'] if result and result[0] else 0
        except Exception as e:
            print(f"获取会话数量失败: {e}")
            return 0
    
    def rename_session(self, session_id, new_name):
        """重命名会话"""
        try:
            self.cursor.execute(
                "UPDATE chat_sessions SET session_name = %s WHERE session_id = %s",
                (new_name, session_id)
            )
            self.connection.commit()
            return True
        except Exception as e:
            print(f"重命名会话失败: {e}")
            return False
    
    def delete_session(self, session_id):
        """删除会话及其历史记录"""
        try:
            # 首先删除历史记录
            self.cursor.execute("DELETE FROM chat_history WHERE session_id = %s", (session_id,))
            # 然后删除会话
            self.cursor.execute("DELETE FROM chat_sessions WHERE session_id = %s", (session_id,))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"删除会话失败: {e}")
            return False
    
    def get_system_stats(self):
        """获取系统统计数据"""
        try:
            query = '''
                SELECT 
                    (SELECT COUNT(*) FROM users) as total_users,
                    (SELECT COUNT(*) FROM chat_sessions) as total_sessions,
                    (SELECT COUNT(*) FROM chat_history) as total_messages,
                    (SELECT COUNT(*) FROM announcements) as total_announcements,
                    (SELECT COUNT(*) FROM users WHERE role = 'admin') as total_roles
            '''
            result = self._execute_query(query, fetch=True)
            return result[0] if result else {
                'total_users': 0,
                'total_sessions': 0,
                'total_messages': 0,
                'total_announcements': 0,
                'total_roles': 0
            }
        except Exception as e:
            print(f"获取统计数据失败: {e}")
            return {
                'total_users': 0,
                'total_sessions': 0,
                'total_messages': 0,
                'total_announcements': 0,
                'total_roles': 0
            }
    
    def get_recent_users(self, limit=5):
        """获取最近注册的用户"""
        try:
            query = '''
                SELECT user_id, username, email, created_at
                FROM users
                ORDER BY created_at DESC
                LIMIT %s
            '''
            return self._execute_query(query, (limit,), fetch=True) or []
        except Exception as e:
            print(f"获取最近用户失败: {e}")
            return []

    def get_users(self, page=1, per_page=10, search=None):
        """获取用户列表"""
        try:
            offset = (page - 1) * per_page
            params = []
            
            # 基础查询
            query = """
                SELECT 
                    user_id, username, email, role, status, 
                    DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as created_at
                FROM users
                WHERE 1=1
            """
            
            # 添加搜索条件
            if search:
                query += " AND (username LIKE %s OR email LIKE %s)"
                search_param = f"%{search}%"
                params.extend([search_param, search_param])
            
            # 添加分页
            query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, offset])
            
            # 获取用户列表
            users = self._execute_query(query, params, fetch=True)
            
            # 获取总数
            count_query = "SELECT COUNT(*) as total FROM users"
            if search:
                count_query += " WHERE username LIKE %s OR email LIKE %s"
                count_params = [f"%{search}%", f"%{search}%"]
            else:
                count_params = []
            
            result = self._execute_query(count_query, count_params, fetch=True)
            total = result[0]['total'] if result else 0
            
            return {
                'users': users or [],
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
            
        except Exception as e:
            print(f"获取用户列表失败: {e}")
            traceback.print_exc()
            return None

    def update_user(self, user_id, data):
        """更新用户信息"""
        try:
            # 开始事务
            self.connection.start_transaction()
            
            # 构建更新字段
            updates = []
            params = []
            
            if 'username' in data:
                updates.append("username = %s")
                params.append(data['username'])
                
            if 'email' in data:
                updates.append("email = %s")
                params.append(data['email'])
                
            if 'password' in data:
                updates.append("password_hash = %s")
                params.append(generate_password_hash(data['password']))
                
            if 'role' in data:
                updates.append("role = %s")
                params.append(data['role'])
                
            if 'status' in data:
                updates.append("status = %s")
                params.append(data['status'])
            
            if not updates:
                return False
            
            # 添加用户ID
            params.append(user_id)
            
            # 执行更新
            query = f"""
                UPDATE users 
                SET {', '.join(updates)}
                WHERE user_id = %s
            """
            
            if not self._execute_query(query, params):
                raise Exception("更新用户信息失败")
            
            # 提交事务
            self.connection.commit()
            return True
            
        except Exception as e:
            # 回滚事务
            self.connection.rollback()
            print(f"更新用户失败: {e}")
            traceback.print_exc()
            return False

    def delete_user(self, user_id):
        """删除用户"""
        try:
            # 开始事务
            self.connection.start_transaction()
            
            # 检查是否为最后一个管理员
            admin_count = self._execute_query(
                "SELECT COUNT(*) as count FROM users WHERE role = 'admin'",
                fetch=True
            )
            
            if admin_count and admin_count[0]['count'] <= 1:
                user = self._execute_query(
                    "SELECT role FROM users WHERE user_id = %s",
                    [user_id],
                    fetch=True
                )
                if user and user[0]['role'] == 'admin':
                    raise Exception("不能删除最后一个管理员")
            
            # 删除用户
            query = "DELETE FROM users WHERE user_id = %s"
            if not self._execute_query(query, [user_id]):
                raise Exception("删除用户失败")
            
            # 提交事务
            self.connection.commit()
            return True
            
        except Exception as e:
            # 回滚事务
            self.connection.rollback()
            print(f"删除用户失败: {e}")
            traceback.print_exc()
            return False

    def get_user_details(self, user_id):
        """获取用户详细信息"""
        try:
            self.cursor.execute("""
                SELECT u.*, 
                    COUNT(DISTINCT ch.session_id) as session_count,
                    COUNT(ch.id) as message_count,
                    MAX(ch.timestamp) as last_active
                FROM users u
                LEFT JOIN chat_history ch ON u.user_id = ch.user_id
                WHERE u.user_id = %s
                GROUP BY u.user_id
            """, (user_id,))
            return self.cursor.fetchone()
        except Exception as e:
            print(f"获取用户详情失败: {e}")
            return None

    def create_announcement(self, title, content, created_by, status='draft'):
        """创建公告"""
        try:
            query = '''
                INSERT INTO announcements (title, content, created_by, status)
                VALUES (%s, %s, %s, %s)
            '''
            if self._execute_query(query, (title, content, created_by, status)):
                # 获取新创建的公告ID
                self.cursor.execute("SELECT LAST_INSERT_ID()")
                announcement_id = self.cursor.fetchone()['LAST_INSERT_ID()']
                print(f"成功创建公告，ID: {announcement_id}")
                return announcement_id
            
            raise Exception("创建公告失败")
            
        except Exception as e:
            print(f"创建公告失败: {e}")
            traceback.print_exc()
            return None

    def update_announcement(self, announcement_id, title, content, status):
        """更新公告"""
        try:
            query = '''
                UPDATE announcements 
                SET title = %s, content = %s, status = %s
                WHERE id = %s
            '''
            self.cursor.execute(query, (title, content, status, announcement_id))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"更新公告失败: {e}")
            return False

    def get_announcements(self, status=None, page=1, per_page=10):
        """获取公告列表"""
        try:
            # 构建基础查询
            query = '''
                SELECT a.*, u.username as author
                FROM announcements a
                LEFT JOIN users u ON a.created_by = u.user_id
            '''
            params = []
            
            # 添加状态过滤
            if status:
                query += ' WHERE a.status = %s'
                params.append(status)
            
            # 添加排序和分页
            query += ' ORDER BY a.created_at DESC LIMIT %s OFFSET %s'
            offset = (page - 1) * per_page
            params.extend([per_page, offset])
            
            # 执行查询
            announcements = self._execute_query(query, params, fetch=True) or []
            
            # 获取总数
            count_query = 'SELECT COUNT(*) as count FROM announcements'
            if status:
                count_query += ' WHERE status = %s'
                count_result = self._execute_query(count_query, (status,), fetch=True)
            else:
                count_result = self._execute_query(count_query, fetch=True)
            
            total = count_result[0]['count'] if count_result else 0
            
            return {
                'announcements': announcements,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        except Exception as e:
            print(f"获取公告列表失败: {e}")
            return {'announcements': [], 'total': 0, 'pages': 0}

    def get_announcement(self, announcement_id):
        """获取单个公告详情"""
        try:
            query = '''
                SELECT a.*, u.username as author
                FROM announcements a
                LEFT JOIN users u ON a.created_by = u.user_id
                WHERE a.id = %s
            '''
            result = self._execute_query(query, (announcement_id,), fetch=True)
            return result[0] if result else None
        except Exception as e:
            print(f"获取公告详情失败: {e}")
            return None

    def delete_announcement(self, announcement_id):
        """删除公告"""
        try:
            self.cursor.execute("DELETE FROM announcements WHERE id = %s", (announcement_id,))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"删除公告失败: {e}")
            return False

    def mark_announcement_read(self, announcement_id, user_id):
        """标记公告为已读"""
        try:
            query = '''
                INSERT INTO announcement_reads (announcement_id, user_id)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE read_at = CURRENT_TIMESTAMP
            '''
            self.cursor.execute(query, (announcement_id, user_id))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"标记公告已读失败: {e}")
            return False

    def get_unread_announcements(self, user_id):
        """获取用户未读公告"""
        try:
            query = """
                SELECT a.* 
                FROM announcements a
                LEFT JOIN announcement_reads ar ON a.id = ar.announcement_id 
                    AND ar.user_id = %s
                WHERE a.status = 'published' 
                    AND ar.id IS NULL
                ORDER BY a.created_at DESC
            """
            
            result = self._execute_query(query, [user_id], fetch=True)
            if result is None:
                return []
            
            announcements = []
            for row in result:
                announcements.append({
                    'id': row['id'],
                    'title': row['title'],
                    'content': row['content'],
                    'created_at': row['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                })
            
            return announcements
            
        except Exception as e:
            print(f"获取未读公告失败: {e}")
            traceback.print_exc()
            return []

    def create_survey(self, title, description, questions, created_by, status='draft'):
        """创建新问卷"""
        try:
            # 创建问卷
            query = '''
                INSERT INTO surveys (title, description, created_by, status)
                VALUES (%s, %s, %s, %s)
            '''
            if not self._execute_query(query, (title, description, created_by, status)):
                raise Exception("创建问卷失败")
            
            # 获取新创建的问卷ID
            result = self._execute_query(
                "SELECT LAST_INSERT_ID() as id",
                fetch=True
            )
            if not result:
                raise Exception("获取问卷ID失败")
            
            survey_id = result[0]['id']
            
            # 添加问题
            for i, q in enumerate(questions):
                query = '''
                    INSERT INTO survey_questions 
                    (survey_id, question_text, question_type, options, required, order_num)
                    VALUES (%s, %s, %s, %s, %s, %s)
                '''
                if not self._execute_query(query, (
                    survey_id, 
                    q['text'],
                    q['type'],
                    json.dumps(q.get('options', [])),
                    q.get('required', True),
                    i + 1
                )):
                    raise Exception(f"添加问题失败: {q['text']}")
            
            print(f"成功创建问卷，ID: {survey_id}, 状态: {status}")  # 添加日志
            return survey_id
            
        except Exception as e:
            print(f"创建问卷失败: {e}")
            traceback.print_exc()  # 添加错误堆栈跟踪
            return None

    def get_surveys(self, status=None, page=1, per_page=10):
        """获取问卷列表"""
        try:
            print(f"开始查询问卷列表，状态: {status}")  # 添加调试信息
            
            # 构建基础查询
            query = '''
                SELECT s.*, u.username as author, 
                       (SELECT COUNT(*) FROM survey_responses WHERE survey_id = s.id) as response_count
                FROM surveys s
                JOIN users u ON s.created_by = u.user_id
            '''
            params = []
            
            # 添加状态过滤
            if status:
                query += ' WHERE s.status = %s'
                params.append(status)
                print(f"添加状态过滤: {status}")  # 添加调试信息
            
            # 添加排序和分页
            query += ' ORDER BY s.created_at DESC LIMIT %s OFFSET %s'
            offset = (page - 1) * per_page
            params.extend([per_page, offset])
            
            print(f"执行查询: {query}")  # 添加调试信息
            print(f"查询参数: {params}")  # 添加调试信息
            
            # 执行查询
            surveys = self._execute_query(query, params, fetch=True)
            print(f"查询到的问卷: {surveys}")  # 添加调试信息
            
            # 获取总数
            count_query = 'SELECT COUNT(*) as count FROM surveys'
            if status:
                count_query += ' WHERE status = %s'
                count_result = self._execute_query(count_query, [status], fetch=True)
            else:
                count_result = self._execute_query(count_query, fetch=True)
            
            total = count_result[0]['count'] if count_result else 0
            print(f"问卷总数: {total}")  # 添加调试信息
            
            result = {
                'surveys': surveys,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
                'page': page
            }
            print(f"返回结果: {result}")  # 添加调试信息
            return result
            
        except Exception as e:
            print(f"获取问卷列表失败: {e}")  # 添加错误日志
            traceback.print_exc()  # 打印完整的错误堆栈
            return {'surveys': [], 'total': 0, 'pages': 0, 'page': page}

    def get_survey(self, survey_id):
        """获取问卷详情"""
        try:
            # 获取问卷基本信息
            query = '''
                SELECT s.*, u.username as author
                FROM surveys s
                JOIN users u ON s.created_by = u.user_id
                WHERE s.id = %s
            '''
            survey = self._execute_query(query, [survey_id], fetch=True)
            if not survey:
                return None
            
            survey = survey[0]
            
            # 获取问题列表
            questions_query = '''
                SELECT id, question_text, question_type, required, options, order_num
                FROM survey_questions
                WHERE survey_id = %s
                ORDER BY order_num
            '''
            questions = self._execute_query(questions_query, [survey_id], fetch=True)
            
            # 处理问题选项
            for question in questions:
                if question['options']:
                    question['options'] = json.loads(question['options'])
                
            survey['questions'] = questions
            print(f"获取到的问卷详情: {survey}")  # 添加日志
            return survey
            
        except Exception as e:
            print(f"获取问卷详情失败: {e}")  # 添加错误日志
            return None

    def get_survey_question(self, question_id):
        """获取问题详情"""
        try:
            query = '''
                SELECT sq.*, s.id as survey_id
                FROM survey_questions sq
                JOIN surveys s ON sq.survey_id = s.id
                WHERE sq.id = %s
            '''
            result = self._execute_query(query, [question_id], fetch=True)
            if result:
                question = result[0]
                if question['options']:
                    question['options'] = json.loads(question['options'])
                return question
            return None
        except Exception as e:
            print(f"获取问题详情失败: {e}")
            traceback.print_exc()
            return None

    def submit_survey(self, survey_id, user_id, answers):
        """提交问卷答案"""
        try:
            # 开始事务
            self.connection.start_transaction()
            
            # 创建答卷记录
            query = '''
                INSERT INTO survey_responses (survey_id, user_id)
                VALUES (%s, %s)
            '''
            if not self._execute_query(query, (survey_id, user_id)):
                raise Exception("创建答卷记录失败")
            
            # 获取新创建的答卷ID
            response_id = self.cursor.lastrowid
            
            # 保存答案
            for answer in answers:
                question_id = answer['question_id']
                
                # 获取问题类型
                question = self.get_survey_question(question_id)
                if not question:
                    raise Exception(f"问题不存在: {question_id}")
                
                if question['question_type'] == 'text':
                    # 文本答案
                    query = '''
                        INSERT INTO survey_answers 
                        (response_id, question_id, answer_text)
                        VALUES (%s, %s, %s)
                    '''
                    if not self._execute_query(query, (
                        response_id, 
                        question_id,
                        answer.get('text', '')
                    )):
                        raise Exception("保存文本答案失败")
                else:
                    # 选项答案
                    query = '''
                        INSERT INTO survey_answers 
                        (response_id, question_id, answer_options)
                        VALUES (%s, %s, %s)
                    '''
                    if not self._execute_query(query, (
                        response_id,
                        question_id,
                        json.dumps(answer.get('options', []))
                    )):
                        raise Exception("保存选项答案失败")
            
            # 更新提交时间
            query = '''
                UPDATE survey_responses 
                SET submitted_at = CURRENT_TIMESTAMP
                WHERE id = %s
            '''
            if not self._execute_query(query, (response_id,)):
                raise Exception("更新提交时间失败")
            
            # 提交事务
            self.connection.commit()
            return True
            
        except Exception as e:
            # 回滚事务
            self.connection.rollback()
            print(f"提交问卷答案失败: {e}")
            traceback.print_exc()
            return False

    def get_survey_responses(self, survey_id, page=1, per_page=10):
        """获取问卷回复"""
        try:
            # 获取总数
            count_query = '''
                SELECT COUNT(DISTINCT sr.id) as count
                FROM survey_responses sr
                WHERE sr.survey_id = %s
            '''
            count_result = self._execute_query(count_query, (survey_id,), fetch=True)
            total = count_result[0]['count'] if count_result else 0
            
            # 如果不需要分页，获取所有数据
            if page is None:
                per_page = total
                page = 1
            
            # 获取回复列表
            query = '''
                SELECT sr.id, sr.submitted_at, u.username,
                       sa.question_id, sq.question_text, sq.question_type,
                       sa.answer_text, sa.answer_options
                FROM survey_responses sr
                JOIN users u ON sr.user_id = u.user_id
                JOIN survey_answers sa ON sr.id = sa.response_id
                JOIN survey_questions sq ON sa.question_id = sq.id
                WHERE sr.survey_id = %s
                ORDER BY sr.submitted_at DESC, sr.id, sq.order_num
                LIMIT %s OFFSET %s
            '''
            
            offset = (page - 1) * per_page
            results = self._execute_query(query, (survey_id, per_page, offset), fetch=True)
            
            # 整理数据结构
            responses = {}
            for row in results:
                response_id = row['id']
                if response_id not in responses:
                    responses[response_id] = {
                        'id': response_id,
                        'username': row['username'],
                        'submitted_at': row['submitted_at'],
                        'answers': []
                    }
                
                answer = {
                    'question_id': row['question_id'],
                    'question_text': row['question_text'],
                    'question_type': row['question_type'],
                    'answer_text': row['answer_text']
                }
                
                if row['answer_options']:
                    answer['answer_options'] = json.loads(row['answer_options'])
                
                responses[response_id]['answers'].append(answer)
            
            return {
                'responses': list(responses.values()),
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
            
        except Exception as e:
            print(f"获取问卷回复失败: {e}")
            return {'responses': [], 'total': 0, 'pages': 0}

    def _check_connection(self):
        """检查并确保数据库连接可用"""
        try:
            max_retries = 3
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    if not self.connection.is_connected():
                        self.connection.ping(reconnect=True)
                        self.cursor = self.connection.cursor(dictionary=True, buffered=True)
                    return True
                except mysql.connector.Error as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise
                    print(f"数据库连接检查失败，第{retry_count}次重试: {e}")
                    # 重新连接
                    try:
                        self.connection = mysql.connector.connect(**{**DB_CONFIG, **DB_POOL_CONFIG})
                        self.cursor = self.connection.cursor(dictionary=True, buffered=True)
                    except:
                        pass
                    time.sleep(1)  # 等待1秒后重试
            
        except Exception as e:
            print(f"数据库连接检查失败: {e}")
            traceback.print_exc()
            return False

    def _execute_query(self, query, params=None, fetch=False):
        """执行查询并处理结果"""
        try:
            max_retries = 3
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    # 检查连接是否有效
                    if not self.connection.is_connected():
                        self.connection.ping(reconnect=True)
                        # 重新创建游标
                        self.cursor = self.connection.cursor(dictionary=True, buffered=True)
                    
                    # 执行查询
                    self.cursor.execute(query, params or ())
                    
                    if fetch:
                        result = self.cursor.fetchall()
                        if result is None:  # 处理空结果
                            return []
                        return result
                    else:
                        self.connection.commit()
                        return True
                    
                except mysql.connector.Error as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise
                    print(f"数据库查询失败，第{retry_count}次重试: {e}")
                    # 重新连接
                    try:
                        self.connection = mysql.connector.connect(**{**DB_CONFIG, **DB_POOL_CONFIG})
                        self.cursor = self.connection.cursor(dictionary=True, buffered=True)
                    except:
                        pass
                    time.sleep(1)  # 等待1秒后重试
            
        except Exception as e:
            print(f"数据库查询失败: {e}")
            traceback.print_exc()
            return None if fetch else False

    def update_survey_status(self, survey_id, status):
        """更新问卷状态"""
        try:
            query = '''
                UPDATE surveys 
                SET status = %s
                WHERE id = %s
            '''
            if self._execute_query(query, (status, survey_id)):
                print(f"成功更新问卷状态，ID: {survey_id}, 新状态: {status}")  # 添加日志
                return True
            return False
        except Exception as e:
            print(f"更新问卷状态失败: {e}")
            traceback.print_exc()  # 添加错误堆栈跟踪
            return False

    def update_survey(self, survey_id, title, description, status, questions):
        """更新问卷"""
        try:
            # 开始事务
            self.connection.start_transaction()
            
            # 更新问卷基本信息
            query = '''
                UPDATE surveys 
                SET title = %s, description = %s, status = %s
                WHERE id = %s
            '''
            if not self._execute_query(query, (title, description, status, survey_id)):
                raise Exception("更新问卷基本信息失败")
            
            # 删除原有问题
            if not self._execute_query("DELETE FROM survey_questions WHERE survey_id = %s", (survey_id,)):
                raise Exception("删除原有问题失败")
            
            # 添加新问题
            for i, q in enumerate(questions):
                query = '''
                    INSERT INTO survey_questions 
                    (survey_id, question_text, question_type, options, required, order_num)
                    VALUES (%s, %s, %s, %s, %s, %s)
                '''
                if not self._execute_query(query, (
                    survey_id, 
                    q['text'],
                    q['type'],
                    json.dumps(q.get('options', [])),
                    q.get('required', True),
                    i + 1
                )):
                    raise Exception(f"添加问题失败: {q['text']}")
            
            # 提交事务
            self.connection.commit()
            print(f"成功更新问卷，ID: {survey_id}")
            return True
            
        except Exception as e:
            # 回滚事务
            self.connection.rollback()
            print(f"更新问卷失败: {e}")
            traceback.print_exc()
            return False

    def init_default_survey(self):
        """初始化默认的情感反馈问卷"""
        try:
            # 检查是否已存在问卷
            result = self._execute_query("SELECT id FROM surveys WHERE title = '情感对话体验反馈'", fetch=True)
            if result:
                return
            
            # 创建默认问卷
            survey_data = {
                'title': '情感对话体验反馈',
                'description': '为了提供更好的服务，请您花几分钟时间完成这份问卷。您的反馈对我们很重要。',
                'status': 'published',
                'questions': [
                    {
                        'text': '您使用情感对话机器人的频率是？',
                        'type': 'single_choice',
                        'required': True,
                        'options': ['每天多次', '每天一次', '每周几次', '偶尔使用', '首次使用']
                    },
                    {
                        'text': '您主要在什么情况下会使用情感对话机器人？（可多选）',
                        'type': 'multiple_choice',
                        'required': True,
                        'options': ['心情不好时', '需要建议时', '感到孤独时', '好奇尝试', '日常聊天', '其他']
                    },
                    {
                        'text': '您认为机器人的情感理解准确度如何？',
                        'type': 'single_choice',
                        'required': True,
                        'options': ['非常准确', '比较准确', '一般', '不太准确', '完全不准确']
                    },
                    {
                        'text': '机器人的回复是否对您有帮助？',
                        'type': 'single_choice',
                        'required': True,
                        'options': ['非常有帮助', '比较有帮助', '一般', '帮助不大', '完全没帮助']
                    },
                    {
                        'text': '使用过程中，您最满意的方面是什么？（可多选）',
                        'type': 'multiple_choice',
                        'required': True,
                        'options': ['回复速度快', '情感理解准确', '建议实用', '对话自然流畅', '隐私保护好', '界面简洁易用']
                    },
                    {
                        'text': '使用过程中，您觉得需要改进的地方是什么？（可多选）',
                        'type': 'multiple_choice',
                        'required': True,
                        'options': ['情感理解能力', '回复内容深度', '对话连贯性', '回复速度', '界面设计', '功能多样性']
                    },
                    {
                        'text': '使用情感对话机器人后，您的心情是否有所改善？',
                        'type': 'single_choice',
                        'required': True,
                        'options': ['显著改善', '有些改善', '没有变化', '反而更糟', '说不清']
                    },
                    {
                        'text': '您对情感对话机器人还有什么建议和期待？',
                        'type': 'text',
                        'required': False
                    }
                ]
            }
            
            # 获取管理员用户ID
            admin = self._execute_query("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1", fetch=True)
            if not admin:
                return
            
            admin_id = admin[0]['user_id']
            
            # 创建问卷
            self.create_survey(
                survey_data['title'],
                survey_data['description'],
                survey_data['questions'],
                admin_id,
                survey_data['status']
            )
            
            print("成功创建默认问卷")
            
        except Exception as e:
            print(f"创建默认问卷失败: {e}")
            traceback.print_exc()

    def get_survey_stats(self, survey_id):
        """获取问卷统计数据"""
        try:
            stats = {
                'total_responses': 0,
                'completion_rate': 0.0,
                'avg_time': 0,
                'daily_responses': [],
                'questions': []
            }
            
            # 获取问卷信息
            survey = self.get_survey(survey_id)
            if not survey:
                return stats
            
            # 获取总回复数
            query = "SELECT COUNT(*) as count FROM survey_responses WHERE survey_id = %s"
            result = self._execute_query(query, [survey_id], fetch=True)
            total_responses = result[0]['count'] if result else 0
            stats['total_responses'] = total_responses
            
            if total_responses > 0:
                # 计算完成率（完整回答所有问题的比例）
                query = """
                    SELECT COUNT(DISTINCT sr.id) as completed
                    FROM survey_responses sr
                    JOIN survey_answers sa ON sr.id = sa.response_id
                    WHERE sr.survey_id = %s
                    GROUP BY sr.id
                    HAVING COUNT(sa.id) = (
                        SELECT COUNT(*) FROM survey_questions 
                        WHERE survey_id = %s
                    )
                """
                result = self._execute_query(query, [survey_id, survey_id], fetch=True)
                completed_responses = len(result) if result else 0
                stats['completion_rate'] = completed_responses / total_responses
                
                # 计算平均完成时间（分钟）
                query = """
                    SELECT AVG(TIMESTAMPDIFF(MINUTE, created_at, submitted_at)) as avg_time
                    FROM survey_responses
                    WHERE survey_id = %s AND submitted_at IS NOT NULL
                """
                result = self._execute_query(query, [survey_id], fetch=True)
                stats['avg_time'] = round(result[0]['avg_time'] or 0, 1) if result else 0
            
            # 获取每日回复数
            query = """
                SELECT 
                    DATE(submitted_at) as date,
                    COUNT(*) as count
                FROM survey_responses 
                WHERE survey_id = %s AND submitted_at IS NOT NULL
                GROUP BY DATE(submitted_at)
                ORDER BY date DESC
                LIMIT 30
            """
            stats['daily_responses'] = self._execute_query(query, [survey_id], fetch=True) or []
            
            # 获取问题统计
            questions = self._execute_query(
                "SELECT * FROM survey_questions WHERE survey_id = %s ORDER BY order_num",
                [survey_id], fetch=True
            )
            
            for q in questions:
                question_stats = {
                    'question_id': q['id'],
                    'question_text': q['question_text'],
                    'question_type': q['question_type'],
                    'response_count': 0,
                    'avg_length': 0
                }
                
                if q['question_type'] == 'text':
                    # 文本题统计
                    query = """
                        SELECT 
                            COUNT(*) as response_count,
                            AVG(LENGTH(answer_text)) as avg_length,
                            sa.answer_text,
                            sr.submitted_at,
                            u.username
                        FROM survey_answers sa
                        JOIN survey_responses sr ON sa.response_id = sr.id
                        JOIN users u ON sr.user_id = u.user_id
                        WHERE sa.question_id = %s
                        GROUP BY sa.id
                        ORDER BY sr.submitted_at DESC
                        LIMIT 10
                    """
                    result = self._execute_query(query, [q['id']], fetch=True)
                    if result:
                        question_stats.update({
                            'response_count': result[0]['response_count'],
                            'avg_length': round(result[0]['avg_length'] or 0),
                            'recent_answers': result
                        })
                else:
                    # 选择题统计
                    query = """
                        SELECT 
                            JSON_UNQUOTE(JSON_EXTRACT(sa.answer_options, '$[0]')) as option_text,
                            COUNT(*) as count
                        FROM survey_answers sa
                        WHERE sa.question_id = %s
                        GROUP BY JSON_UNQUOTE(JSON_EXTRACT(sa.answer_options, '$[0]'))
                    """
                    question_stats['option_counts'] = self._execute_query(query, [q['id']], fetch=True) or []
                
                stats['questions'].append(question_stats)
            
            return stats
            
        except Exception as e:
            print(f"获取问卷统计失败: {e}")
            traceback.print_exc()
            return None

    def _create_default_roles(self):
        """创建默认角色"""
        try:
            # 检查是否已存在默认角色
            self.cursor.execute("SELECT role_id FROM chatbot_roles WHERE is_default = TRUE")
            if not self.cursor.fetchone():
                # 获取管理员用户ID
                self.cursor.execute("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1")
                admin = self.cursor.fetchone()
                admin_id = admin['user_id'] if admin else None
                
                # 插入默认角色
                self.cursor.execute('''
                    INSERT INTO chatbot_roles (role_id, name, app_id, description, is_default, created_by)
                    VALUES (%s, %s, %s, %s, TRUE, %s)
                ''', ('default', '默认助手', '0283dffc5cbd495cb793347612c3f534', '通用型AI助手', admin_id))
                
                self.connection.commit()
                print("默认角色创建成功")
            else:
                print("默认角色已存在")
        except Exception as e:
            print(f"创建默认角色失败: {e}")
            self.connection.rollback()
            # 出错时重试一次
            try:
                self.cursor.execute('''
                    INSERT INTO chatbot_roles (role_id, name, app_id, description, is_default)
                    VALUES ('default', '默认助手', '0283dffc5cbd495cb793347612c3f534', '通用型AI助手', TRUE)
                    ON DUPLICATE KEY UPDATE
                    name = VALUES(name),
                    app_id = VALUES(app_id),
                    description = VALUES(description),
                    is_default = TRUE
                ''')
                self.connection.commit()
                print("默认角色重试创建成功")
            except Exception as e2:
                print(f"默认角色重试创建也失败了: {e2}")
                self.connection.rollback()

    def get_all_roles(self):
        """获取所有角色"""
        try:
            query = '''
                SELECT r.*, u.username as creator_name
                FROM chatbot_roles r
                LEFT JOIN users u ON r.created_by = u.user_id
                ORDER BY r.is_default DESC, r.created_at DESC
            '''
            roles = self._execute_query(query, fetch=True)
            if not roles:
                # 如果没有角色，确保创建默认角色
                self._create_default_roles()
                roles = self._execute_query(query, fetch=True)
            return roles or []
        except Exception as e:
            print(f"获取角色列表失败: {e}")
            return []

    def create_role(self, role_id, name, app_id, description, created_by):
        """创建新角色"""
        try:
            # 清理输入数据中的空格
            role_id = role_id.strip()
            name = name.strip()
            app_id = app_id.strip()
            description = description.strip() if description else ''
            
            self.cursor.execute('''
                INSERT INTO chatbot_roles (role_id, name, app_id, description, created_by)
                VALUES (%s, %s, %s, %s, %s)
            ''', (role_id, name, app_id, description, created_by))
            self.connection.commit()
            return True
        except Exception as e:
            print(f"创建角色失败: {e}")
            self.connection.rollback()
            return False

    def update_role(self, role_id, name, app_id, description):
        """更新角色"""
        try:
            # 清理输入数据中的空格
            name = name.strip()
            app_id = app_id.strip()
            description = description.strip() if description else ''
            
            self.cursor.execute('''
                UPDATE chatbot_roles
                SET name = %s, app_id = %s, description = %s
                WHERE role_id = %s AND is_default = FALSE
            ''', (name, app_id, description, role_id))
            self.connection.commit()
            return bool(self.cursor.rowcount)
        except Exception as e:
            print(f"更新角色失败: {e}")
            self.connection.rollback()
            return False

    def delete_role(self, role_id):
        """删除角色"""
        try:
            self.cursor.execute('''
                DELETE FROM chatbot_roles
                WHERE role_id = %s AND is_default = FALSE
            ''', (role_id,))
            self.connection.commit()
            return bool(self.cursor.rowcount)
        except Exception as e:
            print(f"删除角色失败: {e}")
            self.connection.rollback()
            return False

    def get_role(self, role_id):
        """获取单个角色信息"""
        try:
            query = '''
                SELECT r.*, u.username as creator_name
                FROM chatbot_roles r
                LEFT JOIN users u ON r.created_by = u.user_id
                WHERE r.role_id = %s
            '''
            result = self._execute_query(query, [role_id], fetch=True)
            return result[0] if result else None
        except Exception as e:
            print(f"获取角色信息失败: {e}")
            return None 