from Protocol import *

#输入数据
file = open('test.bin', 'rb')
content = file.read()
file.close()

#生成解析对象
parse = IPv4(content,0)

#to_string() 函数返回一段字符串，类型为str
print(parse.to_string())

#get(string id) 函数返回一个类，id为xml文档里对应的解析内容的id
reserved = parse.get("Reserved")
print(reserved.to_string())


#get_parse_result()函数用于option对象，返回option部分的解析列表
options = parse.get("TCP_option")
op_list = options.get_parse_result()
for i in op_list:
    print(i.to_string(),end="")
