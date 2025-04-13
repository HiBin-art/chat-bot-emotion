from dashscope import Application
import os
from db_manager import DatabaseManager
from config import API_KEY, APP_ID, CHATBOT_ROLES
import traceback

class EmotionalChatbot:
    def __init__(self):
        self.db = DatabaseManager()
        self.api_key = API_KEY
        self.current_role = 'default'
        default_role = self.db.get_role('default')
        self.app_id = default_role['app_id'] if default_role else APP_ID
    
    def switch_role(self, role_id):
        """切换角色"""
        try:
            print(f"尝试切换到角色: {role_id}")  # 添加日志
            role = self.db.get_role(role_id)
            if role:
                self.current_role = role_id
                self.app_id = role['app_id']
                print(f"成功切换到角色: {role['name']}, APP_ID: {role['app_id']}")  # 添加日志
                return True
            print(f"未找到角色: {role_id}")  # 添加日志
            return False
        except Exception as e:
            print(f"切换角色失败: {e}")
            traceback.print_exc()
            return False
    
    def get_current_role(self):
        """获取当前角色信息"""
        role = self.db.get_role(self.current_role)
        if not role:
            role = self.db.get_role('default')
            if not role:  # 如果连默认角色都不存在
                return {
                    'role_id': 'default',
                    'name': '默认助手',
                    'app_id': APP_ID,
                    'description': '通用型AI助手'
                }
        
        return {
            'role_id': self.current_role,
            'name': role['name'],
            'app_id': role['app_id'],
            'description': role['description']
        }
    
    def get_available_roles(self):
        """获取所有可用角色"""
        roles = self.db.get_all_roles()
        return {role['role_id']: {
            'name': role['name'],
            'app_id': role['app_id'],
            'description': role['description'],
            'creator': role['creator_name'],
            'created_at': role['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        } for role in roles}
    
    def get_response(self, message):
        """获取聊天回复"""
        try:
            # 确保 app_id 没有空格
            app_id = self.app_id.strip() if self.app_id else APP_ID
            print(f"使用 APP_ID: {app_id} 发送消息")  # 添加日志
            
            # 调用星火大模型API
            response = Application.call(
                api_key=self.api_key,
                app_id=app_id,
                prompt=message,
                messages=[{
                    "role": "user",
                    "content": message
                }]
            )
            
            if response.status_code == 200:
                if not hasattr(response, 'output') or not hasattr(response.output, 'text'):
                    print(f"API响应格式错误: {response}")
                    return "抱歉，服务器返回了错误的响应格式。"
                return response.output.text
            else:
                print(f"API调用失败: 状态码 {response.status_code}, 消息: {getattr(response, 'message', '未知错误')}")
                if response.status_code == 403:
                    print(f"APP_ID验证失败，当前APP_ID: '{app_id}'")
                return "抱歉，我现在遇到了一些问题，请稍后再试。"
            
        except Exception as e:
            print(f"获取回复失败: {str(e)}")
            traceback.print_exc()  # 打印完整错误堆栈
            return "抱歉，我现在有点累，能稍后再聊吗？"
    
    def chat(self, user_id, message, session_id=None):
        """处理聊天请求"""
        try:
            # 如果没有session_id，创建新会话
            if not session_id:
                session_id = self.db.create_chat_session(user_id)
                if not session_id:
                    return {
                        'status': 'error',
                        'message': '创建会话失败'
                    }
            
            # 获取历史对话记录
            history = []
            chat_history = self.db.get_chat_history(user_id, session_id)
            for record in chat_history:
                history.extend([
                    {"role": "user", "content": record['message']},
                    {"role": "assistant", "content": record['response']}
                ])
            
            # 调用API，同时使用云端和本地历史记录
            response = Application.call(
                api_key=self.api_key,
                app_id=self.app_id,
                prompt=message,
                session_id=str(session_id),  # 转换为字符串
                messages=history if history else None
            )
            
            if response.status_code == 200:
                # 保存对话历史到本地数据库
                self.db.save_chat_history(
                    user_id,
                    session_id,  # 使用数据库的session_id
                    message,
                    response.output.text
                )
                
                return {
                    'status': 'success',
                    'response': response.output.text,
                    'session_id': session_id  # 返回数据库的session_id
                }
            else:
                return {
                    'status': 'error',
                    'message': f'API错误: {response.message}'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'message': f'系统错误: {str(e)}'
            }
    
    def get_chat_history(self, user_id, session_id):
        """
        获取本地存储的对话历史
        """
        return self.db.get_chat_history(user_id, session_id) 