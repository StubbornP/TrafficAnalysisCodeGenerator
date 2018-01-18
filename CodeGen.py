from engine.TagAgentBuilder import buildTagAgent
from tag.TagRegistry import initTagRegistry
from tag.Tag import Tag
from engine.TagAgent import *
from engine.TagSequence import *
from tag.CPPTag import *

import xml.etree.ElementTree as ET

def Get_Xml_File(File_name):
    file = ET.parse(File_name)
    root = file.getroot()
    return root

def main_code_gen(XML_File_name,lang,output_file_name):
    initTagRegistry()
    XML_root = Get_Xml_File(XML_File_name)
    agent = buildTagAgent(lang)
    Tag_sequence = TagSequence()
#生成每个标签对应的对象
    for child in XML_root:
        if child.tag in ["Init","Container","Protocol"]:
            tag=agent.getTag(child.tag)
            Tag_sequence += tag(child)
    #开始生成代码
    code = ''
    code_for_init = ''
    code_for_mainclass = ''
    code_for_option = ''
    for ele in Tag_sequence:
        if ele.type =="Init":
            code_for_init = ele()
        elif ele.type == "Container":
            code_for_option = ele()
        elif ele.type =="Protocol":
            code_for_mainclass = ele()
    #写进文件
    code = code_for_init + code_for_option+code_for_mainclass
    file = output_file_name+"."+lang.lower()
    file = open(file,'w')
    file.write(code)
    file.close()



if __name__ == "__main__":
    main_code_gen(XML_File_name="test.xml",lang = "CPP",output_file_name = "tcp_protocol")