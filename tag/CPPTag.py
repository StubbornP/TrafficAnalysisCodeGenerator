from tag.Tag import Tag

from regular_expression import *

from tag.Tag import Tag

from regular_expression import *
from engine.TagSequence import *

object_dict = {
    "Field": lambda child: CPPFieldTag(child)(),
    "Switch": lambda child: CPPSwitchTag(child)(),
    "BlockArray": lambda child: CPPBlockArrayTag(child)(),
    "Option": lambda child: CPPOptionTag(child)(),
    "IP4": lambda child: CPPIP4Tag(child)(),
    "IP6": lambda child: CPPIP6Tag(child)(),
    "Mac": lambda child: CPPMacTag(child)(),
    "Pass": lambda child: CPPPassTag(child)(),
    "Break": lambda child: CPPBreakTag(child)(),
    "Parse": lambda child: CPPParseTag(child)(),
    "Bytes":lambda child: CPPBytesTag(child)(),
    "Nop":lambda child: CPPNopTag(child)(),
}

type_dict = {
    "byte": 1,
    "flag": 1,
    "uint": 4,
    "ushort": 2,
    "ulong": 8,
    "uchar": 1
}
define_dict = {
    "byte": "unsigned int ",
    "flag": "unsigned int ",
    "uint": "unsigned int ",
    "ushort": "unsigned int ",
    "ulong": "unsigned long ",
    "uchar": "unsigned char "
}


class CPPInitTag(Tag):
    lang = "CPP"
    type = "Init"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        super(CPPInitTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = """

#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <windows.h>
#include <iomanip>
#include "cJSON.h"
using namespace std;
#include <string>
class Protocol;
class Field;class Protocol {
private:
    char* data;
    int ptr=0;
public:
    string id;
    string value;
    string tag;
    string type;
    stringstream byte_array;
    unsigned long content;
    map<string,unsigned long > reg_dict;
    Protocol()=default;
    virtual void Parse(){};
	virtual Protocol* get(string id) { return nullptr; };
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
	virtual vector<Protocol*> get_parse_result() { return vector<Protocol*>(); };
    /**
        Parameters:
            None
        Returns:
            class: vector<Protocol*>
            only available for a Option class
            return the parse result in Option part in order
        Raises:
            None
    **/
	virtual string to_string() { return nullptr; };
    /**
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
    **/
    virtual int get_ptr(){return this->ptr;}
        /**
        Parameters:
            None
        Returns:
            class: int
            where does the pointer point to after the parse
        Raises:
            None
    **/
    virtual map<string,unsigned long > get_reg_dict(){return this->reg_dict;}
	virtual cJSON* to_json() { return nullptr; };
    /**
        Parameters:
            None
        Returns:
            class: cJSON*
            a pointer to a cJSON object which contains all the parse result
            only available in the main Protocol class,can not be used for option object or Field object
        Raises:
            None
    **/
    virtual cJSON* to_json_Option(){ return nullptr; };
        /**
        Parameters:
            None
        Returns:
            class: cJSON*
            a interface for Option class
            do not use this function
        Raises:
            None
    **/
};
class Field:public Protocol{
private:
    char* data;
    int ptr=0;
public:
    map<string,int> tag_dict;
    unsigned long content;
    int left=0;
    int right =0;
    int bytes=0;
    Field()= default;
    Field(string tag,string id,char* data,int left,int right,int bytes){
        this->type = "Field";
        this->tag = tag;
        this->id =id;
        this->data = data;
        this->content=0;
        this->left = left;
        this->right =right;
        this->bytes=bytes;
        this->value = auto_format();
        for(int i =0;i<this->bytes;i++){
            this->byte_array<<this->data[i];
        }
    }
    unsigned long get_num(){
        return this->content;
    }
    string auto_format(){
        switch (tag_to_int(this->tag)){
            case(2):return IP4_format();
            case(3):return IP6_format();
            case(4):return Mac_format();
            case(1):return Field_format();
            case(5):return Bytes_format();
            default:
                return "";
        }
    }
    int tag_to_int(string id){
        tag_dict["Field"]=1;
        tag_dict["IP4"]=2;
        tag_dict["IP6"]=3;
        tag_dict["Mac"]=4;
        tag_dict["Bytes"]=5;
        return tag_dict[id];
    }

    string to_string() override {
        return this->id + ": "+this->value+"\\n";
    }
    string Field_format(){
        unsigned long num = read_num(0,this->bytes);
        stringstream stream;
        if((this->left!=0) || (this->right!=0)){
            num =bit_filter(num,this->bytes,this->left,this->right);
        }
        stream<<num;
        this->content=num;
        return stream.str();
    }
    string IP4_format(){
        string str="";
        long num;
        stringstream stream;
        for(int i =0;i<4;i++){
            num = read_num(i,1);
            stream << num;
            if(i<3){stream<<".";}
        }
        return stream.str();
    }
    string IP6_format(){
        stringstream stream;
        long num;
        for(int i =0;i<8;i++){
            num = read_num(i*2,2);
            stream << setfill ('0') << setw(4)
                   << std::hex << num;
            if(i<7){stream<<":";}
        }
        return stream.str();
    }
    string Mac_format(){
        stringstream stream;
        long right;
        unsigned long num;
        for(int i =0;i<6;i++){
            num = read_num(i,1);
            stream << setfill ('0') << setw(2)
                   << std::hex << num;
            if(i<5){stream<<"-";}
        }
        return stream.str();
    }
    string Bytes_format(){
        stringstream stream;
        long right;
        unsigned long num;
        for(int i =0;i<this->bytes;i++){
            num = read_num(i,1);
            stream << "\\\\0x"<<setfill ('0') << setw(2)
                   << std::hex << num;
        }
        return stream.str();
    }
    static unsigned long bit_filter(unsigned long data,int bytes,int start_bit,int end_bit){
        long left = (1<<(8*bytes-start_bit))-1;
        long right = (8*bytes-end_bit);
        data = data & left;
        data = data >> right;
        return data;
    }
    unsigned long read_num(int ptr,int bytes)  {
        unsigned long content = 0;
        for(int i = 0;i<bytes;i++){
            content = content<<8;
            content+=(unsigned char)this->data[ptr];
            ptr+=1;
        }
        return content;
    }
};

"""
        return code


class CPPFieldTag(Tag):
    lang = "CPP"
    type = "Field"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        super(CPPFieldTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        start_bit = 0 if 'bits' not in self.info.keys() else self.info['bits'].split(":")[0]
        end_bit = 0 if 'bits' not in self.info.keys() else self.info['bits'].split(":")[1]
        reg = '' if 'reg' not in self.info.keys() else self.info['reg']
        cursor = 1 if 'cursor' not in self.info.keys() else 0
        code = "Field_parse(\"Field\",\"{}\",{},{},{},{},\"{}\");\n".format(self.info['id'],
                                                                            type_dict[self.info['type']], start_bit,
                                                                            end_bit, cursor, reg)
        return code


class CPPOptionTag(Tag):
    lang = "CPP"
    type = "Option"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPOptionTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = ''
        if "ref" in self.info:
            code = """
    Option_{}* option_{}=new Option_{}(&this->data[0],this->ptr,this->reg_dict);
    this->parse_result[\"{}\"]=option_{};                
    parse_vector.emplace_back(make_pair(\"{}\",option_{}));
    this->reg_dict = option_{}->get_reg_dict();
    this->ptr = option_{}->get_ptr(); """.format(self.info['ref'], self.info['ref'], self.info['ref'],  self.info['ref'],  self.info['ref'], self.info['ref'],
                                               self.info['ref'], self.info['ref'], self.info['ref'])
        elif "id" in self.info:
            code = """
class Option_{} :public Protocol{{
private:
    char* data;
    int ptr=0;
public:
    vector<Protocol*> parse_result_list;
    vector<Protocol*>::iterator parse_result_iter;
    Option_{}(){{}};
    Option_{}(char * data,int ptr,map<string,unsigned long> reg_dict){{
        this->type = "Option";
        this->ptr = ptr;
        this->data = data;
        this->reg_dict = reg_dict;

        if ({}){{
            Parse();
            }}
    }}
    vector<Protocol*> get_parse_result(){{
        return this->parse_result_list;
    }}
    void Field_parse(string tag, string id, int bytes,int left,int right,int cursor,string reg){{
        Field* parse = new Field(tag,id,&this->data[this->ptr],left,right,bytes);
        if (cursor!= 0){{
            this->ptr +=bytes;
        }}
        if (reg!=""){{
            content = parse->get_num();
            this->reg_dict[reg]=content;
        }}
        this->parse_result_list.emplace_back(parse);
    }}
        string to_string() override{{
        string str="";
        for (this->parse_result_iter = parse_result_list.begin();this->parse_result_iter!=parse_result_list.end(); this->parse_result_iter++){{
            str += (**this->parse_result_iter).to_string();
        }}
        return str;
    }}
    cJSON * to_json_Option() override {{
        cJSON * root;
        unsigned long tmp_num;
        root=cJSON_CreateObject();
        for (this->parse_result_iter = parse_result_list.begin();this->parse_result_iter!=parse_result_list.end(); this->parse_result_iter++){{
                if((**this->parse_result_iter).tag=="Field"){{
                    istringstream iss((**this->parse_result_iter).value);
                    iss>>tmp_num;
                    cJSON_AddNumberToObject(root,(**this->parse_result_iter).id.c_str(),tmp_num);
                }} else{{
                    cJSON_AddStringToObject(root,(**this->parse_result_iter).id.c_str(),(**this->parse_result_iter).value.c_str());

                }}
        }}
        return root;
    }}""".format(self.info["id"], self.info["id"], self.info["id"], CPP_expression_trans(self.info["expression"]))
            for child in self.child:
                code += object_dict[child.tag](child)
        code += "};\n"
        return code


class CPPBlockArrayTag(Tag):
    lang = "CPP"
    type = "BlockArray"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPBlockArrayTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()

        return code

    def generate_code(self):
        if 'ref' in self.info.keys():
            code = "BlockArray_{}();".format(self.info['ref'])
        elif 'id' in self.info.keys():
            code = """
    void BlockArray_{}(){{
        int tmp_ptr = this->ptr;
        long length = {};
        while (this->ptr < tmp_ptr+length){{\n""".format(self.info['id'], CPP_expression_trans(self.info['size']))
            for child in self.child:
                code += "            "
                code += object_dict[child.tag](child)
            code += "\n}\n}"
        return code


class CPPSwitchTag(Tag):
    lang = "CPP"
    type = "Switch"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPSwitchTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        if 'id' in self.info.keys():
            code = """
    void Switch_{}(){{\n""".format(self.info['id'])
            for child in self.child:
                code += "        "
                code += object_dict[child.tag](child)
            code += '\n}\n'
        elif 'ref' in self.info.keys():
            code = "if({}){{Switch_{}();}}\n".format(CPP_expression_trans(self.info["expression"]), self.info['ref'])
        return code


class CPPContainerTag(Tag):
    lang = "CPP"
    type = "Container"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()

        super(CPPContainerTag, self).__init__(xmlObject)

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


class CPPParseTag(Tag):
    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPParseTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = """
    void Parse(){
"""
        for child in self.child:
            code += "        "
            code += object_dict[child.tag](child)
        code += "}"
        return code


class CPPProtocolTag(Tag):
    lang = "CPP"
    type = "Protocol"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPProtocolTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code_for_case = self.generate_code(kwargs)
        return code_for_case

    def generate_code(self, kwargs):
        code = """
class {} : public Protocol{{
private:
    char* data;
    int ptr=0;
public:
    {}(){{}}
    map<string,Protocol*> parse_result;
    vector<pair<string,Protocol*>> parse_vector;
    vector<pair<string,Protocol*>>::iterator iter_vector;
    {}(char* data,int ptr){{
        this->type = "Protocol";
        this->data = data;
        this->ptr = ptr;
        this->Parse();
    }}

    void Field_parse(string tag, string id, int bytes,int left,int right,int cursor,string reg){{
        Field* parse = new Field(tag,id,&this->data[this->ptr],left,right,bytes);
        if (cursor!= 0){{
            this->ptr +=bytes;
        }}
        if (reg!=""){{
            content = parse->get_num();
            this->reg_dict[reg]=content;
        }}
        parse_result[id]=parse;
        parse_vector.emplace_back(make_pair(id,parse));
    }}

    Protocol* get(string id){{
        if(this->parse_result.count(id)>0){{
            return this->parse_result[id];
        }} else{{
            return NULL;
        }}
    }};
    string to_string() override {{
        string str="";
        for(iter_vector =parse_vector.begin();iter_vector!=parse_vector.end();iter_vector++){{
            str+=iter_vector->second->to_string();
        }}
        return str;
    }};
    cJSON* to_json() override {{
        cJSON *root;
        unsigned long tmp_num;
        root=cJSON_CreateObject();
        for (iter_vector =parse_vector.begin();iter_vector!=parse_vector.end();iter_vector++){{
            if(iter_vector->second->type=="Field"){{
             if(iter_vector->second->tag=="Field"){{
                    istringstream iss(iter_vector->second->value);
                    iss>>tmp_num;
                    cJSON_AddNumberToObject(root,iter_vector->first.c_str(),tmp_num);
                }} else{{
                    cJSON_AddStringToObject(root,iter_vector->first.c_str(),iter_vector->second->value.c_str());

                }}
            }}
            else if(iter_vector->second->type=="Option"){{
                cJSON_AddItemToObject(root,iter_vector->first.c_str(),iter_vector->second->to_json_Option());
            }}
        }}
        return root;
    }}
    void Parse(){{

""".format(self.info["id"], self.info["id"], self.info["id"])
        for child in self.child:
            if child.tag in object_dict.keys():
                code += "    "
                code += object_dict[child.tag](child)
        code += '\n};'

        return code


class CPPIP4Tag(Tag):
    lang = "CPP"
    type = "IP4"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPIP4Tag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"IP4\", \"{}\", 4, 0, 0, 1, \"\");\n".format(self.info['id'])
        return code


class CPPIP6Tag(Tag):
    lang = "CPP"
    type = "IP6"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPIP6Tag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"IP6\", \"{}\", 16, 0, 0, 1, \"\");\n".format(self.info['id'])
        return code


class CPPMacTag(Tag):
    lang = "CPP"
    type = "Mac"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPMacTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"Mac\", \"{}\", 6, 0, 0, 1, \"\");\n".format(self.info['id'])
        return code

class CPPNopTag(Tag):
    lang = "CPP"
    type = "Nop"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPNopTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "this->ptr = {};\n".format(self.info['position'])
        return code


class CPPBytesTag(Tag):
    lang = "CPP"
    type = "Bytes"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPBytesTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "Field_parse(\"Bytes\", \"{}\", {}, 0, 0, 1, \"\");\n".format(self.info['id'],CPP_expression_trans(self.info["length"]))
        return code


class CPPPassTag(Tag):
    lang = "CPP"
    type = "Pass"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPPassTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = ""
        return code


class CPPBreakTag(Tag):
    lang = "CPP"
    type = "Break"

    def __init__(self, xmlObject):
        self.info = xmlObject.attrib
        self.child = xmlObject.getchildren()
        super(CPPBreakTag, self).__init__(xmlObject)

    def __call__(self, *args, **kwargs):
        code = self.generate_code()
        return code

    def generate_code(self):
        code = "if ({}){{break;}}\n".format(CPP_expression_trans(self.info['expression']))
        return code