from tag.Tag import Tag

from regular_expression import *
from engine.TagSequence import *

object_dict = {
    "Field": lambda child: PYFieldTag(child)(),
    "Switch": lambda child: PYSwitchTag(child)(),
    "BlockArray": lambda child: PYBlockArrayTag(child)(),
    "Option": lambda child: PYOptionTag(child)(),
    "IP4": lambda child: PYIP4Tag(child)(),
    "IP6": lambda child: PYIP6Tag(child)(),
    "Mac": lambda child: PYMacTag(child)(),
    "Pass": lambda child: PYPassTag(child)(),
    "Break": lambda child: PYBreakTag(child)(),
    "Container":lambda child:PYContainerTag(child)(),
    "Parse":lambda child:PYParseTag(child)(),
    "Nop":lambda child:PYNopTag(child)(),
    "Bytes":lambda child:PYBytesTag(child)()
}

type_dict={
"byte"  : '1',
"flag"  : '1',
"uint"  : '4',
"ushort": '2',
"ulong" : '8',
"uchar" : '1',
    "tribytes":"1"
}
class PYInitTag(Tag):
    lang = "PY"
    type = "Init"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        super(PYInitTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = """

#Python3.60
import json
"""
        code += """

class Protocol():

    def __init__(self, data):
        self.data = data
        self.ptr = 0
        self.reg_dict={}
        self.parse_result = {}

    def __call__(self, *args, **kwargs):
        return self

    def __str__(self):
        return self.to_string()

    def get(self,id):
        \"\"\"
        Parameters:
            id :
                class: string
                id must be the id of a tag in XML file
        Returns:
            class: Field
            an object which contains the parse result
        Raises:
            None
        \"\"\"
        if id in self.parse_result:
            return self.parse_result[id]
        else:
            raise KeyError("There is no {} in the parse result".format(id))

    def Field_parse(self,tag,id,bytes,left,right,cursor,reg):
        content = self.read_content(self.ptr, bytes)
        parse =Field(tag=tag, id=id,content=content,left = left,right =right,bytes =bytes)
        if cursor == None:
            self.ptr += bytes
        if reg != None:
            self.reg_dict[reg] = int(parse.get_value())
        self.parse_result[id]= parse

    def read_content(self, ptr, length):
        return self.data[ptr:ptr + length]

    def to_string(self):
        \"\"\"
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
        \"\"\"
        string = ""
        for i in self.parse_result.keys():
            string += self.parse_result[i].to_string()
        return string
        
    def to_json(self):
        \"\"\"
        Parameters:
            None
        Returns:
            class: dict
            a json which includes all the parse result
        Raises:
            None
        \"\"\"
        json_dict = {}
        for key in self.parse_result.keys():
            json_dict[key] = self.parse_result[key].to_json()
        target_json = json.loads(json.dumps(json_dict))
        return target_json
        
class Field():

    def __init__(self,**kwargs):
        self.tag = kwargs["tag"]
        self.id = kwargs["id"]
        self.content = kwargs["content"]
        self.left = kwargs["left"]
        self.right = kwargs["right"]
        self.bytes =kwargs["bytes"]
        self.value = self.__auto_format()
        self.byte_array = self.content

    def __call__(self, *args, **kwargs):
        return self

    def get_value(self):
        return self.value

    def __auto_format(self):
        format_dict = {
            "Field":self.__Field_format(),
            "IP4": self.__IP4_format(),
            "IP6":self.__IP6_format(),
            "Mac":self.__Mac_format(),
            "Bytes":self.__Bytes_format()
        }
        if self.tag in format_dict.keys():
            return format_dict[self.tag]
        else:
            raise KeyError("This tag is not legal:"+self.tag)
    
    def to_string(self):
        \"\"\"
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
        \"\"\"
        return self.id + ": "+str(self.value) + "\\n"
        
    def to_json(self):
        \"\"\"
        Parameters:
            None
        Returns:
            class: dict
            a json which includes all the parse result
            if there is any option in the parse result,the options will be saved in order in a list
            only available in the main Protocol class,can not be used for option object or Field object
        Raises:
            None
        \"\"\"
        if self.tag == "Field":
            return int(self.value)
        else :
            return self.value

    def __Field_format(self):
        content = int.from_bytes(self.content, byteorder="big")
        if (self.left!=None) and (self.right!=None):
            content = self.bit_filter(content, self.left,self.right, self.bytes)
        return str(content)

    def __IP4_format(self):
        local_string = ''
        tmp = 0
        for i in self.content:
            local_string += str(i)
            if tmp < 3:
                local_string += '.'
            tmp += 1
        return local_string

    def __IP6_format(self):
        local_string = ''
        tmp = 0
        for i in self.content:
            local_string += "%02X" % i
            if (tmp < 15) and (tmp > 0) and (tmp % 2 == 1):
                local_string += ':'
            tmp += 1
        return local_string

    def __Mac_format(self):
        local_string = ''
        tmp_ptr = 0
        for i in self.content:
            local_string += "%02X" % i
            if (tmp_ptr < 5) :
                local_string += '-'
            tmp_ptr += 1
        return local_string
        
    def __Bytes_format(self):
        local_string = ''
        local_string+=''.join('\\\\0x%.2x' % x for x in self.content)
        self.byte_array = self.content
        return local_string
        
    @staticmethod
    def bit_filter(data, left,right, bytes):
        value = data
        left = (1 << (8 * bytes - int(left))) - 1
        right = (8 * bytes - int(right))
        data = value & left
        data = data >> right
        return data
"""
        return code


class PYFieldTag(Tag):
    lang = "PY"
    type = "Field"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        super(PYFieldTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        if 'bits' not in self.info.keys():
            left = "None"
            right = "None"
        else:
            left = self.info["bits"].split(":")[0]
            right = self.info["bits"].split(":")[1]
        reg = 'None' if 'reg' not in self.info.keys() else "\"" + self.info['reg'] + "\""
        cursor = 'None' if 'cursor' not in self.info.keys() else self.info['cursor']
        code = "self.Field_parse(\"Field\", \"{}\", {}, {}, {}, {}, {})\n".format(self.info['id'], type_dict[self.info['type']], left, right,cursor, reg)
        return code


class PYOptionTag(Tag):
    lang = "PY"
    type = "Option"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYOptionTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = ""
        if "ref" in self.info:
            code = "self.parse_result[\"{}\"],self.ptr,self.reg_dict=Option_{}(data =self.data,ptr=self.ptr,reg_dict=self.reg_dict)()".format(self.info['ref'], self.info['ref'])
        elif "id" in self.info:
            code = """
class Option_{}(Protocol):

    def __init__(self,data,**kwargs):
        super(Option_{},self).__init__(data)
        self.parse_result =[]
        if 'ptr' in kwargs.keys():
            self.ptr = kwargs['ptr']
        if "data" in kwargs.keys():
            self.data = kwargs["data"]
        if "reg_dict"  in kwargs.keys():
            self.reg_dict = kwargs["reg_dict"]
        if ({}):
            self.__Parse()
            
    def __call__(self):
        return self,self.reg_dict,self.ptr
    
    def to_string(self):
        \"\"\"
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
        \"\"\"
        option_string =""
        for i in self.parse_result:
            option_string +=i.to_string()
        return option_string
        
    def to_json(self):
        \"\"\"
        Parameters:
            None
        Returns:
            class: dict
            a json which includes all the parse result
        Raises:
            None
        \"\"\"
        json_list = []
        for parse_result in self.parse_result:
            json_list.append(json.loads(json.dumps({{parse_result.id: parse_result.to_json()}})))
        return json_list
        
    def get_parse_result(self):
        return self.parse_result
        
    def Field_parse(self,tag,id,bytes,left,right,cursor,reg):
        content = self.read_content(self.ptr, bytes)
        parse =Field(tag=tag, id=id,content=content,left = left,right =right,bytes =bytes)
        if cursor == None:
            self.ptr += bytes
        if reg != None:
            self.reg_dict[reg] = int(parse.get_value())
        self.parse_result.append(parse)
        """.format(self.info["id"], self.info["id"], PY_expression_trans(self.info["expression"]))
            for child in self.child:
                code += object_dict[child.tag](child)
        return code


class PYBlockArrayTag(Tag):
    lang = "PY"
    type = "BlockArray"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYBlockArrayTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        if 'ref' in self.info.keys():
            code = "self.BlockArray_{}()".format(self.info['ref'])
        elif 'id' in self.info.keys():
            code = """
    def BlockArray_{}(self):
        tmp_ptr = self.ptr
        length = {}
        while self.ptr < tmp_ptr+length:\n""".format(self.info['id'], PY_expression_trans(self.info['size']))
            for child in self.child:
                code += "           "
                code += object_dict[child.tag](child)
        return code

class PYParseTag(Tag):

    def __init__(self,xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYParseTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = """
    def __Parse(self):
"""
        for child in self.child:
            code +="        "
            code += object_dict[child.tag](child)

        return code

class PYSwitchTag(Tag):
    lang = "PY"
    type = "Switch"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYSwitchTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        if 'id' in self.info.keys():
            code = """
    def __Switch_{}(self):\n""".format(self.info['id'])
            for child in self.child:
                code += "       "
                code += object_dict[child.tag](child)
            code += '\n'
        elif 'ref' in self.info.keys():
            code = "if({}):self.__Switch_{}()\n".format(PY_expression_trans(self.info["expression"]),self.info['ref'])
        return code


class PYContainerTag(Tag):
    lang = "PY"
    type = "Container"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYContainerTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        code = ''
        for child in self.child:
            code += "       "
            code += object_dict[child.tag](child)
        code += '\n'
        return code


class PYProtocolTag(Tag):
    lang = "PY"
    type = "Protocol"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYProtocolTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code_for_case = self.generate_code(kwargs)
        return code_for_case

    def generate_code(self, kwargs):
        code = """
class {}(Protocol):

    def __init__(self, data,ptr, **kwargs):
        super({},self).__init__(data)
        self.ptr = ptr 
        self.__Parse()

    def __call__(self, *args, **kwargs):
        return self.parse_result

    def __Parse(self): 
""".format(self.info['id'],self.info['id'])
        for child in self.child:
            if child.tag in object_dict.keys():
                code += "        "
                code += object_dict[child.tag](child)
        code +="""
       
if __name__ =="__main__":
    file = open('tcp.bin','rb')
    content = file.read()
    file.close()
    parse = {}(content,0)
    print(parse.to_string())
    print(parse.to_json())
        """.format(self.info['id'])
        return code


class PYIP4Tag(Tag):
    lang = "PY"
    type = "IP4"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYIP4Tag, self).__init__(xmlObject)


    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "self.Field_parse(\"IP4\", \"{}\", 4, None, None, None, None)\n".format(self.info['id'])
        return code


class PYIP6Tag(Tag):
    lang = "PY"
    type = "IP6"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYIP6Tag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "self.Field_parse(\"IP6\", \"{}\", 16, None, None, None, None)\n".format(self.info['id'])
        return code


class PYMacTag(Tag):
    lang = "PY"
    type = "Mac"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYMacTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "self.Field_parse(\"Mac\", \"{}\", 6, None, None, None, None)\n".format(self.info['id'])
        return code


class PYBytesTag(Tag):
    lang = "PY"
    type = "Bytes"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYBytesTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "self.Field_parse(\"Bytes\", \"{}\", {}, None, None, None, None)\n".format(self.info['id'],PY_expression_trans(self.info["length"]))
        return code

class PYNopTag(Tag):
    lang = "PY"
    type = "Nop"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYNopTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "self.ptr = {}\n".format(self.info["position"])
        return code

class PYPassTag(Tag):
    lang = "PY"
    type = "Pass"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYPassTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "pass\n"
        return code


class PYBreakTag(Tag):
    lang = "PY"
    type = "Break"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(PYBreakTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "if ({}):break\n".format(PY_expression_trans(self.info['expression']))
        return code