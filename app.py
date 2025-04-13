from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, send_from_directory
from functools import wraps
from chatbot import EmotionalChatbot
from db_manager import DatabaseManager
import traceback
import json
from flask_wtf.csrf import CSRFProtect, generate_csrf
from datetime import datetime
import os
from PIL import Image, ImageDraw
from flask_cors import CORS
import mysql.connector
from requests.exceptions import ConnectionError
from config import (
    DB_CONFIG, DB_POOL_CONFIG, STATIC_CONFIG, SECURITY_CONFIG, 
    SERVER_CONFIG, CHATBOT_ROLES, APP_ID  # 添加 APP_ID 导入
)

# 修改应用配置
app = Flask(__name__, **STATIC_CONFIG)

# 配置应用
app.config.update(SECURITY_CONFIG)

# 启用 CSRF 保护
csrf = CSRFProtect(app)

# 配置 CORS
CORS(app, supports_credentials=True, resources={
    r"/*": {
        "origins": ["http://127.0.0.1:5000"],  # 限制来源
        "allow_headers": ["Content-Type", "X-CSRF-TOKEN"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "supports_credentials": True
    }
})

db = DatabaseManager()
chatbot = EmotionalChatbot()

# 修改 CSRF 配置
def configure_csrf_exempt():
    """配置 CSRF 豁免"""
    # API 路由豁免
    csrf.exempt(api_chat)
    csrf.exempt(get_chat_history)
    csrf.exempt(get_sessions)
    csrf.exempt(create_session)
    csrf.exempt(rename_session)
    csrf.exempt(delete_session)
    csrf.exempt(update_user_api)  # 更新为新的用户管理API
    csrf.exempt(delete_user_api)  # 添加删除用户API豁免
    csrf.exempt(get_unread_announcements)
    csrf.exempt(mark_announcement_read)
    csrf.exempt(submit_survey)
    csrf.exempt(create_survey)
    csrf.exempt(create_announcement)
    csrf.exempt(delete_announcement)
    csrf.exempt(export_survey_responses)

# 修改 CSRF token 处理
@app.after_request
def after_request(response):
    """为所有响应添加必要的头部"""
    # 添加 CSRF token
    if 'text/html' in response.headers.get('Content-Type', ''):
        response.set_cookie('csrf_token', generate_csrf())
    
    # 添加安全头部
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Origin', request.headers.get('Origin', '*'))
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-TOKEN')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    
    return response

# 登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 管理员验证装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('需要管理员权限')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.verify_user(username, password)
        if user:
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['role'] = user['role']
            # 如果是管理员，重定向到管理面板
            if user['role'] == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('chat'))
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        
        if not username or not password or not email:
            flash('所有字段都必须填写')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('两次输入的密码不一致')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('密码长度必须至少为6个字符')
            return render_template('register.html')
        
        if db.register_user(username, password, email):
            flash('注册成功，请登录')
            return redirect(url_for('login'))
        else:
            flash('注册失败，用户名或邮箱已存在')
    
    return render_template('register.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', username=session['username'])

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    """处理聊天请求"""
    try:
        data = request.get_json()
        message = data.get('message')
        session_id = data.get('session_id')
        
        if not message:
            return jsonify({
                'status': 'error',
                'message': '消息不能为空'
            }), 400
        
        # 获取当前角色信息
        current_role = chatbot.get_current_role()
        print(f"当前使用角色: {current_role}")  # 添加日志
        
        # 获取聊天回复
        response = chatbot.get_response(message)
        if not response:
            raise Exception("获取回复失败")
        
        # 保存聊天记录
        if session_id:
            db.save_chat_history(
                session['user_id'],
                session_id,
                message,
                response
            )
        
        return jsonify({
            'status': 'success',
            'response': response
        })
        
    except Exception as e:
        print(f"处理聊天请求失败: {str(e)}")
        traceback.print_exc()  # 打印完整错误堆栈
        return jsonify({
            'status': 'error',
            'message': f'处理聊天请求失败: {str(e)}'
        }), 500

@app.route('/api/history/<session_id>')
@login_required
def get_chat_history(session_id):
    """获取指定会话的历史记录"""
    history = chatbot.get_chat_history(session['user_id'], session_id)
    return jsonify({
        'status': 'success',
        'history': history
    })

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    """管理员面板"""
    # 获取统计数据
    stats = db.get_system_stats()
    # 获取最近注册的用户
    recent_users = db.get_recent_users()
    
    return render_template('admin.html', 
                         stats=stats,
                         recent_users=recent_users)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    try:
        sessions = db.get_user_sessions(session['user_id'])
        return jsonify({
            'status': 'success',
            'sessions': sessions
        })
    except Exception as e:
        print(f"获取会话列表失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/sessions', methods=['POST'])
@login_required
def create_session():
    """创建新会话"""
    session_name = request.json.get('name')
    session_id = db.create_chat_session(session['user_id'], session_name)
    if session_id:
        return jsonify({
            'status': 'success',
            'session_id': session_id
        })
    return jsonify({'status': 'error', 'message': '创建会话失败'})

@app.route('/api/sessions/<int:session_id>', methods=['PUT'])
@login_required
def rename_session(session_id):
    """重命名会话"""
    new_name = request.json.get('name')
    if db.rename_session(session_id, new_name):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': '重命名失败'})

@app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def delete_session(session_id):
    """删除会话"""
    if db.delete_session(session_id):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': '删除失败'})

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """用户管理页面"""
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search')
        
        # 使用新的 get_users 方法
        result = db.get_users(page=page, search=search)
        if not result:
            flash('获取用户列表失败')
            return redirect(url_for('admin_panel'))
            
        return render_template('admin/users.html', **result)
        
    except Exception as e:
        print(f"访问用户管理页面失败: {e}")
        traceback.print_exc()
        flash('访问用户管理页面失败')
        return redirect(url_for('admin_panel'))

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user_api(user_id):
    """更新用户信息"""
    try:
        data = request.get_json()
        
        # 验证数据
        if not data:
            return jsonify({
                'status': 'error',
                'message': '无效的请求数据'
            }), 400
            
        # 不允许修改最后一个管理员的角色
        if 'role' in data and data['role'] != 'admin':
            admin_count = db._execute_query(
                "SELECT COUNT(*) as count FROM users WHERE role = 'admin'",
                fetch=True
            )
            if admin_count and admin_count[0]['count'] <= 1:
                user = db._execute_query(
                    "SELECT role FROM users WHERE user_id = %s",
                    [user_id],
                    fetch=True
                )
                if user and user[0]['role'] == 'admin':
                    return jsonify({
                        'status': 'error',
                        'message': '不能修改最后一个管理员的角色'
                    }), 400
        
        # 更新用户信息
        if db.update_user(user_id, data):
            return jsonify({
                'status': 'success',
                'message': '更新成功'
            })
            
        return jsonify({
            'status': 'error',
            'message': '更新失败'
        }), 500
        
    except Exception as e:
        print(f"更新用户失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user_api(user_id):
    """删除用户"""
    try:
        if db.delete_user(user_id):
            return jsonify({
                'status': 'success',
                'message': '删除成功'
            })
            
        return jsonify({
            'status': 'error',
            'message': '删除失败'
        }), 500
        
    except Exception as e:
        print(f"删除用户失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/admin/announcements')
@login_required
@admin_required
def admin_announcements():
    """公告管理页面"""
    try:
        page = request.args.get('page', 1, type=int)
        result = db.get_announcements(page=page)
        return render_template('admin/announcements.html', **result)
    except Exception as e:
        print(f"获取公告列表失败: {e}")
        traceback.print_exc()
        flash('获取公告列表失败')
        return redirect(url_for('admin_panel'))

@app.route('/announcements/<int:id>')
@login_required
def view_announcement(id):
    """查看公告详情"""
    try:
        announcement = db.get_announcement(id)
        if not announcement:
            flash('公告不存在')
            return redirect(url_for('view_announcements'))
            
        # 如果是普通用户，只能查看已发布的公告
        if session['role'] != 'admin' and announcement['status'] != 'published':
            flash('无权查看该公告')
            return redirect(url_for('view_announcements'))
            
        return render_template('announcement_detail.html', announcement=announcement)
        
    except Exception as e:
        print(f"查看公告详情失败: {e}")
        traceback.print_exc()
        flash('查看公告详情失败')
        return redirect(url_for('view_announcements'))

@app.route('/api/announcements/unread')
@login_required
def get_unread_announcements():
    """获取未读公告"""
    try:
        # 检查数据库连接
        if not db.connection.is_connected():
            db.connection.ping(reconnect=True)
        
        announcements = db.get_unread_announcements(session['user_id'])
        return jsonify({
            'status': 'success',
            'announcements': announcements
        })
    except Exception as e:
        print(f"获取未读公告失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/announcements/<int:announcement_id>/read', methods=['POST'])
@login_required
def mark_announcement_read(announcement_id):
    """标记公告为已读"""
    try:
        # 检查公告是否存在
        announcement = db._execute_query(
            "SELECT id FROM announcements WHERE id = %s",
            [announcement_id],
            fetch=True
        )
        
        if not announcement:
            return jsonify({
                'status': 'error',
                'message': '公告不存在'
            }), 404
            
        # 添加阅读记录
        result = db._execute_query("""
            INSERT IGNORE INTO announcement_reads 
                (announcement_id, user_id) 
            VALUES (%s, %s)
        """, [announcement_id, session['user_id']])
        
        if result is None:
            return jsonify({
                'status': 'error',
                'message': '标记已读失败'
            }), 500
            
        return jsonify({
            'status': 'success',
            'message': '标记已读成功'
        })
        
    except Exception as e:
        print(f"标记公告已读失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/check-session')
def check_session():
    """检查会话状态"""
    try:
        if 'user_id' not in session:
            return jsonify({
                'status': 'error',
                'message': '未登录'
            }), 401
            
        # 检查用户是否存在且状态正常
        user = db._execute_query(
            "SELECT status FROM users WHERE user_id = %s",
            [session['user_id']],
            fetch=True
        )
        
        if not user:
            session.clear()  # 清除无效会话
            return jsonify({
                'status': 'error',
                'message': '用户不存在'
            }), 404
            
        if user[0]['status'] != 'active':
            session.clear()  # 清除禁用用户的会话
            return jsonify({
                'status': 'error',
                'message': '账户已禁用，请联系管理员',
                'code': 'account_disabled'
            }), 403
            
        return jsonify({
            'status': 'success',
            'user_id': session['user_id'],
            'username': session.get('username'),
            'role': session.get('role', 'user')
        })
        
    except Exception as e:
        print(f"检查会话状态失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/admin/surveys')
@login_required
@admin_required
def admin_surveys():
    """问卷管理页面"""
    page = request.args.get('page', 1, type=int)
    result = db.get_surveys(page=page)
    return render_template('admin/surveys.html', **result)

@app.route('/admin/surveys/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_survey():
    """创建问卷"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            title = data.get('title')
            description = data.get('description')
            status = data.get('status')  # 获取状态
            questions = data.get('questions')
            
            if not title or not questions:
                return jsonify({
                    'status': 'error',
                    'message': '标题和问题不能为空'
                }), 400
            
            # 创建问卷，传入状态参数
            survey_id = db.create_survey(title, description, questions, session['user_id'], status)
            if survey_id:
                return jsonify({
                    'status': 'success',
                    'survey_id': survey_id
                })
            return jsonify({
                'status': 'error',
                'message': '创建问卷失败'
            }), 500
            
        except Exception as e:
            print(f"创建问卷失败: {e}")
            traceback.print_exc()  # 添加错误堆栈跟踪
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    
    return render_template('admin/survey_form.html')

@app.route('/surveys')
@login_required
def view_surveys():
    """查看问卷列表"""
    try:
        page = request.args.get('page', 1, type=int)
        print("正在获取已发布的问卷...")  # 添加调试信息
        result = db.get_surveys(status='published', page=page)
        print(f"获取到的问卷列表: {result}")  # 添加调试信息
        
        if not result['surveys']:
            print("没有找到任何已发布的问卷")  # 添加调试信息
            
        # 检查问卷状态
        for survey in result.get('surveys', []):
            print(f"问卷ID: {survey.get('id')}, 标题: {survey.get('title')}, 状态: {survey.get('status')}")
            
        return render_template('surveys.html', **result)
    except Exception as e:
        print(f"获取问卷列表失败: {e}")
        traceback.print_exc()  # 打印完整的错误堆栈
        flash('获取问卷列表失败')
        return redirect(url_for('index'))

@app.route('/surveys/<int:id>')
@login_required
def view_survey(id):
    """查看问卷详情"""
    try:
        survey = db.get_survey(id)
        print(f"获取到的问卷详情: {survey}")  # 添加日志
        
        if not survey:
            flash('问卷不存在')
            return redirect(url_for('view_surveys'))
            
        if survey['status'] != 'published':
            flash('问卷未发布')
            return redirect(url_for('view_surveys'))
            
        # 确保问题列表存在且格式正确
        if 'questions' not in survey or not survey['questions']:
            flash('问卷内容不完整')
            return redirect(url_for('view_surveys'))
            
        return render_template('survey_detail.html', survey=survey)
        
    except Exception as e:
        print(f"获取问卷详情失败: {e}")  # 添加错误日志
        flash('获取问卷详情失败')
        return redirect(url_for('view_surveys'))

@app.route('/api/surveys/<int:id>/submit', methods=['POST'])
@login_required
def submit_survey(id):
    """提交问卷"""
    try:
        # 检查问卷是否存在且已发布
        survey = db.get_survey(id)
        if not survey:
            return jsonify({
                'status': 'error',
                'message': '问卷不存在'
            })
        
        if survey['status'] != 'published':
            return jsonify({
                'status': 'error',
                'message': '问卷未发布或已关闭'
            })
        
        # 获取提交的答案
        data = request.get_json()
        if not data or 'answers' not in data:
            return jsonify({
                'status': 'error',
                'message': '提交数据格式错误'
            })
        
        # 验证答案格式
        answers = data['answers']
        if not isinstance(answers, list):
            return jsonify({
                'status': 'error',
                'message': '答案必须是数组'
            })
        
        # 验证每个答案
        for answer in answers:
            if not isinstance(answer, dict) or 'question_id' not in answer:
                return jsonify({
                    'status': 'error',
                    'message': '答案格式错误'
                })
            
            # 检查问题是否存在
            question = db.get_survey_question(answer['question_id'])
            if not question or question['survey_id'] != id:
                return jsonify({
                    'status': 'error',
                    'message': f'问题不存在: {answer["question_id"]}'
                })
            
            # 验证必填项
            if question['required']:
                if question['question_type'] == 'text':
                    if 'text' not in answer or not answer['text'].strip():
                        return jsonify({
                            'status': 'error',
                            'message': f'问题 {question["question_text"]} 为必填项'
                        })
                else:
                    if 'options' not in answer or not answer['options']:
                        return jsonify({
                            'status': 'error',
                            'message': f'问题 {question["question_text"]} 为必填项'
                        })
        
        # 保存答案
        if db.submit_survey(id, session['user_id'], answers):
            return jsonify({
                'status': 'success',
                'message': '提交成功'
            })
        
        return jsonify({
            'status': 'error',
            'message': '提交失败，请重试'
        })
        
    except Exception as e:
        print(f"提交问卷失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/admin/surveys/<int:id>/responses')
@login_required
@admin_required
def view_survey_responses(id):
    """查看问卷回复"""
    try:
        survey = db.get_survey(id)
        if not survey:
            flash('问卷不存在')
            return redirect(url_for('admin_surveys'))
        
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # 获取问卷回复
        responses = db.get_survey_responses(id, page, per_page)
        
        return render_template('admin/survey_responses.html',
                             survey=survey,
                             responses=responses['responses'],
                             page=page,
                             pages=responses['pages'])
                             
    except Exception as e:
        flash(f'获取回复失败: {str(e)}')
        return redirect(url_for('admin_surveys'))

@app.route('/admin/surveys/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_survey(id):
    """编辑问卷"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            title = data.get('title')
            description = data.get('description')
            status = data.get('status')
            questions = data.get('questions')
            
            if not title or not questions:
                return jsonify({
                    'status': 'error',
                    'message': '标题和问题不能为空'
                }), 400
            
            if db.update_survey(id, title, description, status, questions):
                return jsonify({
                    'status': 'success',
                    'survey_id': id
                })
            return jsonify({
                'status': 'error',
                'message': '更新问卷失败'
            }), 500
        
        # GET 请求：获取问卷详情
        survey = db.get_survey(id)
        if not survey:
            flash('问卷不存在')
            return redirect(url_for('admin_surveys'))
            
        return render_template('admin/survey_form.html', survey=survey)
        
    except Exception as e:
        print(f"编辑问卷失败: {e}")
        traceback.print_exc()
        flash('编辑问卷失败')
        return redirect(url_for('admin_surveys'))

@app.route('/admin/surveys/<int:id>/analysis')
@login_required
@admin_required
def survey_analysis(id):
    """问卷数据分析"""
    try:
        survey = db.get_survey(id)
        if not survey:
            flash('问卷不存在')
            return redirect(url_for('admin_surveys'))
            
        # 获取问卷统计数据
        stats = db.get_survey_stats(id)
        
        return render_template('admin/survey_analysis.html',
                             survey=survey,
                             stats=stats)
                             
    except Exception as e:
        print(f"获取问卷分析失败: {e}")
        traceback.print_exc()
        flash('获取分析数据失败')
        return redirect(url_for('admin_surveys'))

@app.route('/admin/surveys/<int:id>/responses/export')
@login_required
@admin_required
def export_survey_responses(id):
    """导出问卷回复"""
    try:
        import pandas as pd
        from io import BytesIO
        
        survey = db.get_survey(id)
        if not survey:
            return jsonify({
                'status': 'error',
                'message': '问卷不存在'
            }), 404
        
        # 获取所有回复
        responses = db.get_survey_responses(id, page=None)['responses']
        
        # 准备Excel数据
        data = []
        for response in responses:
            row = {
                '用户': response['username'],
                '提交时间': response['submitted_at']
            }
            
            # 添加每个问题的答案
            for answer in response['answers']:
                if answer['question_type'] == 'text':
                    row[answer['question_text']] = answer['answer_text']
                else:
                    row[answer['question_text']] = ', '.join(answer.get('answer_options', []))
            
            data.append(row)
        
        # 创建DataFrame
        df = pd.DataFrame(data)
        
        # 创建Excel文件
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='问卷回复', index=False)
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f'问卷回复_{survey["title"]}_{datetime.now().strftime("%Y%m%d")}.xlsx'
        )
        
    except Exception as e:
        print(f"导出问卷回复失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'导出失败: {str(e)}'
        }), 500

@app.route('/admin/announcements/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_announcement():
    """创建公告"""
    try:
        if request.method == 'POST':
            data = request.get_json()
            title = data.get('title')
            content = data.get('content')
            status = data.get('status', 'draft')
            
            if not title or not content:
                return jsonify({
                    'status': 'error',
                    'message': '标题和内容不能为空'
                }), 400
            
            # 确保 user_id 是整数
            user_id = int(session['user_id'])
            
            announcement_id = db.create_announcement(
                title=title,
                content=content,
                created_by=user_id,  # 使用整数类型的user_id
                status=status
            )
            
            if announcement_id:
                return jsonify({
                    'status': 'success',
                    'announcement_id': announcement_id
                })
                
            return jsonify({
                'status': 'error',
                'message': '创建公告失败'
            }), 500
        
        return render_template('admin/announcement_form.html')
        
    except Exception as e:
        print(f"创建公告失败: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/admin/announcements/<int:id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_announcement(id):
    """编辑公告"""
    announcement = db.get_announcement(id)
    if not announcement:
        flash('公告不存在')
        return redirect(url_for('admin_announcements'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        status = request.form.get('status')
        
        if db.update_announcement(id, title, content, status):
            flash('公告更新成功')
            return redirect(url_for('admin_announcements'))
        flash('公告更新失败')
    
    return render_template('admin/announcement_form.html', announcement=announcement)

@app.route('/api/announcements/<int:id>', methods=['DELETE'])
@login_required
@admin_required
def delete_announcement(id):
    """删除公告"""
    if db.delete_announcement(id):
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': '删除失败'})

@app.route('/announcements')
@login_required
def view_announcements():
    """查看公告列表（用户视图）"""
    try:
        page = request.args.get('page', 1, type=int)
        result = db.get_announcements(status='published', page=page)
        return render_template('announcements.html', **result)
    except Exception as e:
        print(f"获取公告列表失败: {e}")
        traceback.print_exc()
        flash('获取公告列表失败')
        return redirect(url_for('index'))

@app.route('/favicon.ico')
def favicon():
    try:
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico',
            mimetype='image/vnd.microsoft.icon'
        )
    except Exception as e:
        print(f"获取 favicon 失败: {e}")
        # 返回一个空的响应而不是错误
        return '', 204

@app.errorhandler(Exception)
def handle_error(error):
    """全局错误处理"""
    print(f"发生错误: {error}")
    traceback.print_exc()
    
    if isinstance(error, mysql.connector.Error):
        return jsonify({
            'status': 'error',
            'message': '数据库连接失败，请稍后重试'
        }), 500
    elif isinstance(error, ConnectionError):
        return jsonify({
            'status': 'error',
            'message': '网络连接失败，请检查网络设置'
        }), 503
    elif isinstance(error, Exception):
        return jsonify({
            'status': 'error',
            'message': str(error)
        }), 500

# 修改数据库连接检查
@app.before_request
def check_db_connection():
    """请求前检查数据库连接"""
    try:
        # 跳过静态文件的数据库检查
        if request.path.startswith('/static/'):
            return
            
        # 跳过 favicon 请求的数据库检查
        if request.path == '/favicon.ico':
            return
            
        # 检查数据库连接
        if not db._check_connection():
            return jsonify({
                'status': 'error',
                'message': '数据库连接失败，请稍后重试'
            }), 500
    except Exception as e:
        print(f"数据库连接检查失败: {e}")
        return jsonify({
            'status': 'error',
            'message': '数据库连接失败，请稍后重试'
        }), 500

# 在应用启动时进行初始化
def create_favicon():
    """创建默认的 favicon"""
    try:
        static_dir = os.path.join(app.root_path, 'static')
        favicon_path = os.path.join(static_dir, 'favicon.ico')
        
        # 确保 static 目录存在
        os.makedirs(static_dir, exist_ok=True)
        
        # 如果图标已存在，直接返回
        if os.path.exists(favicon_path):
            return
            
        # 创建一个空的图标文件
        with open(favicon_path, 'wb') as f:
            f.write(b'')
            
    except Exception as e:
        print(f"创建 favicon 失败: {e}")

def init_app():
    # 配置 CSRF 豁免
    configure_csrf_exempt()
    # 创建 favicon
    create_favicon()
    # 初始化默认问卷
    db.init_default_survey()

@app.route('/api/roles', methods=['GET'])
@login_required
def get_roles():
    """获取所有可用角色"""
    try:
        roles = chatbot.get_available_roles()
        if not roles:
            default_role = chatbot.get_current_role()  # 使用 chatbot 的方法获取默认角色
            return jsonify({
                'status': 'success',
                'current_role': default_role,
                'roles': {'default': default_role}
            })
        return jsonify({
            'status': 'success',
            'current_role': chatbot.get_current_role(),
            'roles': roles
        })
    except Exception as e:
        print(f"获取角色列表失败: {e}")
        # 确保即使出错也返回一个可用的默认角色
        default_role = {
            'role_id': 'default',
            'name': '默认助手',
            'app_id': APP_ID,
            'description': '通用型AI助手'
        }
        return jsonify({
            'status': 'success',
            'current_role': default_role,
            'roles': {'default': default_role}
        })

@app.route('/api/roles/<role_id>', methods=['POST'])
@login_required
def switch_role(role_id):
    """切换角色"""
    try:
        print(f"收到角色切换请求: {role_id}")  # 添加日志
        if chatbot.switch_role(role_id):
            current_role = chatbot.get_current_role()
            print(f"切换成功，当前角色: {current_role}")  # 添加日志
            return jsonify({
                'status': 'success',
                'role': current_role
            })
        print(f"切换失败，角色ID无效: {role_id}")  # 添加日志
        return jsonify({
            'status': 'error',
            'message': '无效的角色ID'
        }), 400
    except Exception as e:
        print(f"切换角色失败: {e}")
        traceback.print_exc()  # 添加错误堆栈
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/roles/<role_id>', methods=['PUT'])
@login_required
@admin_required
def update_role(role_id):
    """更新角色"""
    try:
        data = request.get_json()
        name = data.get('name')
        app_id = data.get('app_id')
        description = data.get('description')
        
        if not all([name, app_id]):
            return jsonify({
                'status': 'error',
                'message': '缺少必要参数'
            }), 400
        
        role = db.get_role(role_id)
        if not role:
            return jsonify({
                'status': 'error',
                'message': '角色不存在'
            }), 404
        
        if db.update_role(role_id, name, app_id, description):
            return jsonify({
                'status': 'success',
                'message': '角色更新成功'
            })
        
        return jsonify({
            'status': 'error',
            'message': '角色更新失败'
        }), 500
        
    except Exception as e:
        print(f"更新角色失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/admin/roles')
@login_required
@admin_required
def admin_roles():
    """角色管理页面"""
    return render_template('admin/roles.html', roles=CHATBOT_ROLES)

@app.route('/api/roles', methods=['POST'])
@login_required
@admin_required
def create_role():
    """创建新角色"""
    try:
        data = request.get_json()
        role_id = data.get('role_id')
        name = data.get('name')
        app_id = data.get('app_id')
        description = data.get('description')
        
        if not all([role_id, name, app_id]):
            return jsonify({
                'status': 'error',
                'message': '缺少必要参数'
            }), 400
            
        if db.create_role(role_id, name, app_id, description, session['user_id']):
            return jsonify({
                'status': 'success',
                'message': '角色创建成功'
            })
        
        return jsonify({
            'status': 'error',
            'message': '角色创建失败'
        }), 500
    except Exception as e:
        print(f"创建角色失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/roles/<role_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_role(role_id):
    """删除角色"""
    try:
        role = db.get_role(role_id)
        if not role:
            return jsonify({
                'status': 'error',
                'message': '角色不存在'
            }), 400
            
        if db.delete_role(role_id):
            return jsonify({
                'status': 'success',
                'message': '角色删除成功'
            })
            
        return jsonify({
            'status': 'error',
            'message': '角色删除失败'
        }), 404
    except Exception as e:
        print(f"删除角色失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    init_app()
    app.run(**SERVER_CONFIG) 