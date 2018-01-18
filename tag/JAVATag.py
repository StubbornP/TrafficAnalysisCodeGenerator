
from tag.Tag import Tag

from regular_expression import *

from tag.Tag import Tag

from regular_expression import *
from engine.TagSequence import *

object_dict = {
    "Field": lambda child: JAVAFieldTag(child)(),
    "Switch": lambda child: JAVASwitchTag(child)(),
    "BlockArray": lambda child: JAVABlockArrayTag(child)(),
    "Option": lambda child: JAVAOptionTag(child)(),
    "IP4": lambda child: JAVAIP4Tag(child)(),
    "IP6": lambda child: JAVAIP6Tag(child)(),
    "Mac": lambda child: JAVAMacTag(child)(),
    "Pass": lambda child: JAVAPassTag(child)(),
    "Break": lambda child: JAVABreakTag(child)(),
    "Parse":lambda child:JAVAParseTag(child)(),
    "Nop": lambda child: JAVANopTag(child)(),
    "Bytes": lambda child: JAVABytesTag(child)()
}

type_dict={
"byte"  : 1,
"flag"  : 1,
"uint"  : 4,
"ushort": 2,
"ulong" : 8,
"uchar" : 1
}
define_dict={
"byte"  : "unsigned int ",
"flag"  : "unsigned int ",
"uint"  : "unsigned int ",
"ushort": "unsigned int ",
"ulong" : "unsigned long ",
"uchar" : "unsigned char "
}
class JAVAInitTag(Tag):
    lang = "JAVA"
    type = "Init"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        super(JAVAInitTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = """
import java.util.*;
import org.json.*;
abstract class Protocol{
    private byte[] data;
    byte[] byte_array;
    private int ptr=0;
    String id= "root";
    String value = "null";
    String type = "Protocol";
    String tag ="default";
    private Map<String,Long> reg_dict =new HashMap();
    Map<String,Protocol> parse_result =new LinkedHashMap<>();
    Protocol(){}

    Protocol(byte[] data,int ptr){
        this.id="";
        this.value="";
        this.data = data;
        this.ptr =ptr;
    }
    /**
    Parameters:
        id :
            class: string
            id must be the id of a tag in XML file
    Returns:
        class: Protocol* or NULL
            if id in the parse result, it will return its parse result(Protocol*)
            or it will return null
            a pointer to an object which contains the parse result
    Raises:
        None
     **/
    Protocol get(String id){
        if(this.parse_result.containsKey(id)){
            return this.parse_result.get(id);
        }
        else return null;
    }
    /**
        Parameters:
            None
        Returns:
            class: int
            where does the pointer point to after the parse
        Raises:
            None
    **/
    int get_ptr(){
        return this.ptr;
    }
    Map<String,Long> get_reg_dict(){
        return reg_dict;
    }

    /**
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
    **/
    public String to_string(){
        String str="";
        for(Protocol parse_result : parse_result.values()){
            str += parse_result.to_string();
            str +="\\n";
        }
        return str;
    }
    /**
        Parameters:
            None
        Returns:
            class: JSONObject
            a pointer to a cJSON object which contains all the parse result
            only available in the main Protocol class,can not be used for option object or Field object 
        Raises:
            None
    **/
    public JSONObject to_json(){
        JSONObject jsonObejct = new JSONObject();
        for(Map.Entry<String,Protocol>  entry : parse_result.entrySet()) {
            if(entry.getValue().type=="Field"){
                if(entry.getValue().tag=="Field"){
            jsonObejct.put(entry.getKey(),Long.valueOf(entry.getValue().value));}
            else {
                jsonObejct.put(entry.getKey(),entry.getValue().value);
            }}
            else if(entry.getValue().type=="Option"){
                jsonObejct.put(entry.getKey(),entry.getValue().to_json_option());
            }
        }
        return jsonObejct;
    }
    /**
        Parameters:
            None
        Returns:
            class: Protocol[]
            only available for a Option class 
            return the parse result in Option part in order
        Raises:
            None
    **/
    abstract Protocol[] get_parse_result();
    /**
        Parameters:
            None
        Returns:
            class: ArrayList
            only available for a Option class 
            return the parse result in Option part in json contains in a list
        Raises:
            None
    **/
    ArrayList to_json_option(){return null;};
}

class Field extends Protocol{
    byte[] content;
    int left=0;
    int right =0;
    int bytes=0;
    Field(){}

    Field(String tag,String id,byte[] content,int left,int right,int bytes){
        this.type = "Field";
        this.tag = tag;
        this.id =id;
        this.content = content;
        this.left = left;
        this.right =right;
        this.bytes =bytes;
        this.value = auto_format();
        this.byte_array = this.content;
    }
    private String auto_format(){
        switch (this.tag){
            case("IP4"):return IP4_format();
            case("IP6"):return IP6_format();
            case("Mac"):return Mac_format();
            case("Field"):return Field_format();
            case("Bytes"):return Bytes_format();
        }
        return "";
    }
    public String to_string(){
        return this.id + ":"+this.value;
    }
    public String to_json_Field() {
        return this.value;
    }
    private long read_num(int ptr,int length){
        long num =0;
        for(int i = 0;i<length;i++){
            num = num*256;
            int unsighed_byte = content[ptr+i] &0xff;
            num+=unsighed_byte;
        }
        return num;
    }
    private String Field_format(){
        long num = read_num(0,this.bytes);
        if((this.left!=0) ||(this.right!=0)){
            num =bit_filter(num,this.bytes,this.left,this.right);
        }
        return String.valueOf(num);
    }
    private String IP4_format(){
        String str="";
        long num;
        for(int i =0;i<4;i++){
            num = read_num(i,1);
            str += String.valueOf(num);
            if(i<3){str+=".";}
        }
        return str;
    }
    private String IP6_format(){
        String str="";
        long num;
        for(int i =0;i<8;i++){
            num = read_num(i,2);
            str += String.format("%04X",num);
            if(i<7){str+=":";}
        }
        return str;
    }
    
    private String Mac_format(){
        String str="";
        long num;
        for(int i =0;i<6;i++){
            num = read_num(i,1);
            str += String.format("%02X",num);
            if(i<5){str+="-";}
        }
        return str;
    }
    private String Bytes_format(){
        String str = "";
        long num;
        for(int i =0;i<this.bytes;i++){
            num = read_num(i,1);
            str += String.format("\\\\0x%02X",num);
        }
        return str;
    }
    
    private static long bit_filter(long data,int bytes,int start_bit,int end_bit){
        long left = (1<<(8*bytes-start_bit))-1;
        long right = (8*bytes-end_bit);
        data = data & left;
        data = data >> right;
        return data;
    }
    Protocol[] get_parse_result(){return null;};
}

"""
        return code


class JAVAFieldTag(Tag):
    lang = "JAVA"
    type = "Field"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        super(JAVAFieldTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        start_bit = 0 if 'bits' not in self.info.keys() else self.info['bits'].split(":")[0]
        end_bit = 0 if 'bits' not in self.info.keys() else self.info['bits'].split(":")[1]
        reg = 'null' if 'reg' not in self.info.keys() else self.info['reg']
        cursor = 1 if 'cursor' not in self.info.keys() else 0
        code = "Field_parse(\"Field\",\"{}\",{},{},{},{},\"{}\");\n".format(self.info['id'], type_dict[self.info['type']], start_bit,end_bit, cursor, reg)
        return code


class JAVAOptionTag(Tag):
    lang = "JAVA"
    type = "Option"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVAOptionTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = ''
        if "ref" in self.info:
            code = """
    Option_{} option_{}=new Option_{}(this.data,this.ptr,this.reg_dict);
    this.parse_result.put(\"{}\",option_{});                this.reg_dict = option_{}.get_reg_dict();
    this.ptr = option_{}.get_ptr(); """.format(self.info['ref'], self.info['ref'], self.info['ref'],self.info['ref'], self.info['ref'], self.info['ref'],self.info['ref'])
        elif "id" in self.info:
            code = """
class Option_{} extends Protocol{{
    private byte[] data;
    private int ptr=0;
    private Map<String,Long> reg_dict =new HashMap();
    Protocol[] parse_result  = new Protocol[100]; 
    Option_{}(){{}};
    int list_ptr=0;
    
    Option_{}(byte[] data,int ptr,Map<String,Long> reg_dict){{
        this.type = "Option";
        this.ptr = ptr;
        this.data = data;
        this.reg_dict = reg_dict;
        
        if ({}){{
            Parse();
            }}
    }}
    
    public ArrayList to_json_option() {{
               ArrayList ArrayObejct = new ArrayList();
        for(int i =0;i<this.list_ptr;i++) {{
            JSONObject tmp_json = new JSONObject();
            if(this.parse_result[i].tag=="Field"){{
                ArrayObejct.add(tmp_json.put(this.parse_result[i].id,Long.valueOf(this.parse_result[i].value)));
            }}
            else{{
                ArrayObejct.add(tmp_json.put(this.parse_result[i].id,this.parse_result[i].value));
            }}
        }}
        return ArrayObejct ;
    }}
    private byte[] read_content(int ptr,int length){{
        byte[] content = new byte[length];
        System.arraycopy(this.data, ptr, content, 0, length);
        return content;
    }}
    Protocol[] get_parse_result(){{
        return this.parse_result;
    }} 
    
    void Field_parse(String tag, String id, int bytes, int left, int right, int cursor, String reg)
    {{
    byte[] content = read_content(this.ptr, bytes);
    Field parse = new Field(tag, id, content, left, right, bytes);
    if (cursor != 0){{
        this.ptr += bytes;}}
    if (reg != null){{
        long number =Long.parseLong(parse.value);
        this.reg_dict.put(reg,number);}}
    this.parse_result[this.list_ptr] = parse;
    this.list_ptr += 1;
    }}
    
    public String to_string(){{
        String str="";
        for(int i =0;i<this.list_ptr;i++){{
            str+=parse_result[i].to_string();
            str +="\\n";
        }}
        return str;
    }}""".format(self.info["id"],self.info["id"],self.info["id"],JAVA_expression_trans(self.info["expression"]))
            for child in self.child:
                code += object_dict[child.tag](child)
        code +="}\n"
        return code

class JAVABlockArrayTag(Tag):
    lang = "JAVA"
    type = "BlockArray"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVABlockArrayTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        if 'ref' in self.info.keys():
            code = "BlockArray_{}();".format(self.info['ref'])
        elif 'id' in self.info.keys():
            code = """
    private void BlockArray_{}(){{
        int tmp_ptr = this.ptr;
        long length = {};
        while (this.ptr < tmp_ptr+length){{\n""".format(self.info['id'], java_size_trans(self.info['size']))
            for child in self.child:
                code += "            "
                code += object_dict[child.tag](child)
            code +="\n}\n}"
        return code


class JAVASwitchTag(Tag):
    lang = "JAVA"
    type = "Switch"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVASwitchTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        if 'id' in self.info.keys():
            code = """
    private void Switch_{}(){{\n""".format(self.info['id'])
            for child in self.child:
                code += "        "
                code += object_dict[child.tag](child)
            code += '\n}\n'
        elif 'ref' in self.info.keys():
            code = "if({}){{Switch_{}();}}\n".format(java_size_trans(self.info["expression"]),self.info['ref'])
        return code


class JAVAContainerTag(Tag):
    lang = "JAVA"
    type = "Container"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()

        super(JAVAContainerTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        code = ''
        for child in self.child:
            code += "\t"
            code += object_dict[child.tag](child)
        code += '\n'
        return code

class JAVAParseTag(Tag):

    def __init__(self,xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVAParseTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = """
    private void Parse(){
"""
        for child in self.child:
            code +="        "
            code += object_dict[child.tag](child)
        code +="}"
        return code

class JAVAProtocolTag(Tag):
    lang = "JAVA"
    type = "Protocol"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVAProtocolTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code_for_case = self.generate_code(kwargs)
        return code_for_case

    def generate_code(self, kwargs):
        code = """
class {} extends Protocol{{
    private byte[] data;
    private int ptr=0;
    private Map<String,Long> reg_dict =new HashMap();
    {}(){{}}

    {}(byte[] data,int ptr){{
        this.data = data;
        this.ptr = ptr;
        this.Parse();
    }}
    private void Field_parse(String tag, String id, int bytes,int left,int right,int cursor,String reg){{
        byte[] content = read_content(this.ptr,bytes);
        Field parse = new Field(tag,id,content,left,right,bytes);
        if (cursor!= 0){{
            this.ptr +=bytes;
        }}
        if (reg!=null){{
            long number =Long.parseLong(parse.value);
            this.reg_dict.put(reg,number);
        }}
        this.parse_result.put(id,parse);
    }}
    private byte[] read_content(int ptr,int length){{
        byte[] content = new byte[length];
        System.arraycopy(this.data, ptr, content, 0, length);
        return content;
    }}
    Protocol[] get_parse_result(){{return null;}}
    private void Parse(){{
           
""".format(self.info["id"],self.info["id"],self.info["id"])
        for child in self.child:
            if child.tag in object_dict.keys():
                code += "    "
                code += object_dict[child.tag](child)
        code += '\n}'

        return code


class JAVAIP4Tag(Tag):
    lang = "JAVA"
    type = "IP4"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVAIP4Tag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"IP4\", \"{}\", 4, 0, 0, 1, null);\n".format(self.info['id'])
        return code


class JAVAIP6Tag(Tag):
    lang = "JAVA"
    type = "IP6"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVAIP6Tag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"IP6\", \"{}\", 16, 0, 0, 1, null);\n".format(self.info['id'])
        return code


class JAVAMacTag(Tag):
    lang = "JAVA"
    type = "Mac"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVAMacTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"Mac\", \"{}\", 6, 0, 0, 1, null);\n".format(self.info['id'])
        return code

class JAVABytesTag(Tag):
    lang = "JAVA"
    type = "Bytes"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVABytesTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"Bytes\", \"{}\", {}, 0, 0, 1, null);\n".format(self.info['id'],JAVA_expression_trans(self.info["length"]))
        return code

class JAVANopTag(Tag):
    lang = "JAVA"
    type = "Nop"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVANopTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "this.ptr = {};\n".format(self.info['position'])
        return code

class JAVAPassTag(Tag):
    lang = "JAVA"
    type = "Pass"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVAPassTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = ""
        return code


class JAVABreakTag(Tag):
    lang = "JAVA"
    type = "Break"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(JAVABreakTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "if ({}){{break;}}\n".format(java_size_trans(self.info['expression']))
        return code