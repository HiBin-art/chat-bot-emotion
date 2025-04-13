from PIL import Image, ImageDraw

# 创建一个 32x32 的图像
img = Image.new('RGB', (32, 32), color='white')
draw = ImageDraw.Draw(img)

# 绘制一个简单的表情符号
# 外圈
draw.ellipse([2, 2, 29, 29], outline='#2563eb', width=2)
# 眼睛
draw.ellipse([8, 8, 12, 12], fill='#2563eb')
draw.ellipse([20, 8, 24, 12], fill='#2563eb')
# 嘴巴
draw.arc([8, 8, 24, 24], 0, 180, fill='#2563eb', width=2)

# 保存为 ICO 格式
img.save('static/favicon.ico', format='ICO') 