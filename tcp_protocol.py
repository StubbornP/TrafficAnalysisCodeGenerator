

#Python3.60
import json


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
        """
        Parameters:
            id :
                class: string
                id must be the id of a tag in XML file
        Returns:
            class: Field
            an object which contains the parse result
        Raises:
            None
        """
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
        """
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
        """
        string = ""
        for i in self.parse_result.keys():
            string += self.parse_result[i].to_string()
        return string
        
    def to_json(self):
        """
        Parameters:
            None
        Returns:
            class: dict
            a json which includes all the parse result
        Raises:
            None
        """
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
        """
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
        """
        return self.id + ": "+str(self.value) + "\n"
        
    def to_json(self):
        """
        Parameters:
            None
        Returns:
            class: dict
            a json which includes all the parse result
            if there is any option in the parse result,the options will be saved in order in a list
            only available in the main Protocol class,can not be used for option object or Field object
        Raises:
            None
        """
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
        local_string+=''.join('\\0x%.2x' % x for x in self.content)
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
       
class Option_TCP_option(Protocol):

    def __init__(self,data,**kwargs):
        super(Option_TCP_option,self).__init__(data)
        self.parse_result =[]
        if 'ptr' in kwargs.keys():
            self.ptr = kwargs['ptr']
        if "data" in kwargs.keys():
            self.data = kwargs["data"]
        if "reg_dict"  in kwargs.keys():
            self.reg_dict = kwargs["reg_dict"]
        if (self.reg_dict["headerlength"]>5):
            self.__Parse()
            
    def __call__(self):
        return self,self.reg_dict,self.ptr
    
    def to_string(self):
        """
        Parameters:
            None
        Returns:
            class: string
            a report of the parse result
        Raises:
            None
        """
        option_string =""
        for i in self.parse_result:
            option_string +=i.to_string()
        return option_string
        
    def to_json(self):
        """
        Parameters:
            None
        Returns:
            class: dict
            a json which includes all the parse result
        Raises:
            None
        """
        json_list = []
        for parse_result in self.parse_result:
            json_list.append(json.loads(json.dumps({parse_result.id: parse_result.to_json()})))
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
        
    def __Switch_id2(self):
       self.Field_parse("Field", "MSS_length", 1, None, None, None, None)
       self.Field_parse("Field", "MSS_data", 2, None, None, None, None)


    def __Switch_id3(self):
       self.Field_parse("Field", "shift_length", 1, None, None, None, None)
       self.Field_parse("Field", "shift_count", 1, None, None, None, None)


    def __Switch_id4(self):
       self.Field_parse("Field", "SACK_length", 1, None, None, None, None)


    def BlockArray_tcp_options(self):
        tmp_ptr = self.ptr
        length = (self.reg_dict["headerlength"]-5)*4
        while self.ptr < tmp_ptr+length:
           self.Field_parse("Field", "kind", 1, None, None, None, "kind")
           if (self.reg_dict["kind"]==0):break
           if(self.reg_dict["kind"]==2):self.__Switch_id2()
           if(self.reg_dict["kind"]==3):self.__Switch_id3()
           if(self.reg_dict["kind"]==4):self.__Switch_id4()

    def __Parse(self):
        self.BlockArray_tcp_options()

class test_xml(Protocol):

    def __init__(self, data,ptr, **kwargs):
        super(test_xml,self).__init__(data)
        self.ptr = ptr 
        self.__Parse()

    def __call__(self, *args, **kwargs):
        return self.parse_result

    def __Parse(self): 
        self.Field_parse("IP4", "test_ip4", 4, None, None, None, None)
        self.Field_parse("IP6", "test_ip6", 16, None, None, None, None)
        self.Field_parse("Mac", "test_mac", 6, None, None, None, None)
        self.Field_parse("Bytes", "test_bytes", 10, None, None, None, None)
        self.Field_parse("Field", "Source_Port", 2, None, None, None, None)
        self.Field_parse("Field", "Destination_Port", 2, None, None, None, None)
        self.Field_parse("Field", "Sequence_Number", 4, None, None, None, None)
        self.Field_parse("Field", "Acknowledgement_Number", 4, None, None, None, None)
        self.Field_parse("Field", "Data_offset", 1, 0, 4, 0, "headerlength")
        self.Field_parse("Field", "Reserved", 1, 4, 7, 0, None)
        self.Field_parse("Field", "NS", 1, 7, 8, None, None)
        self.Field_parse("Field", "CWR", 1, 0, 1, 0, None)
        self.Field_parse("Field", "ECE", 1, 1, 2, 0, None)
        self.Field_parse("Field", "URG", 1, 2, 3, 0, "flag_URG")
        self.Field_parse("Field", "ACK", 1, 3, 4, 0, None)
        self.Field_parse("Field", "PSH", 1, 4, 5, 0, None)
        self.Field_parse("Field", "RST", 1, 5, 6, 0, None)
        self.Field_parse("Field", "SYN", 1, 6, 7, 0, None)
        self.Field_parse("Field", "FIN", 1, 7, 8, None, None)
        self.Field_parse("Field", "Window_Size", 2, None, None, None, None)
        self.Field_parse("Field", "Checksum", 2, None, None, None, None)
        self.Field_parse("Field", "urgent_ptr", 2, None, None, None, None)
        self.parse_result["TCP_option"],self.ptr,self.reg_dict=Option_TCP_option(data =self.data,ptr=self.ptr,reg_dict=self.reg_dict)()
       
if __name__ =="__main__":
    file = open('tcp.bin','rb')
    content = file.read()
    file.close()
    parse = test_xml(content,0)
    print(parse.to_string())
    print(parse.to_json())
        