from chatbot import EmotionalChatbot

def main():
    chatbot = EmotionalChatbot()
    user_id = 1  # 这里简化处理，假设用户ID为1
    session_id = None
    
    print("欢迎使用情感沟通机器人！输入 'quit' 退出对话。")
    
    while True:
        user_input = input("\n你: ")
        if user_input.lower() == 'quit':
            break
            
        result = chatbot.chat(user_id, user_input, session_id)
        
        if result['status'] == 'success':
            print(f"机器人: {result['response']}")
            session_id = result['session_id']
        else:
            print(f"错误: {result['message']}")

if __name__ == '__main__':
    main() 