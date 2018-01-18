

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
        return this->id + ": "+this->value+"\n";
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
            stream << "\\0x"<<setfill ('0') << setw(2)
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

	
class Option_TCP_option :public Protocol{
private:
    char* data;
    int ptr=0;
public:
    vector<Protocol*> parse_result_list;
    vector<Protocol*>::iterator parse_result_iter;
    Option_TCP_option(){};
    Option_TCP_option(char * data,int ptr,map<string,unsigned long> reg_dict){
        this->type = "Option";
        this->ptr = ptr;
        this->data = data;
        this->reg_dict = reg_dict;

        if (this->reg_dict["headerlength"]>5){
            Parse();
            }
    }
    vector<Protocol*> get_parse_result(){
        return this->parse_result_list;
    }
    void Field_parse(string tag, string id, int bytes,int left,int right,int cursor,string reg){
        Field* parse = new Field(tag,id,&this->data[this->ptr],left,right,bytes);
        if (cursor!= 0){
            this->ptr +=bytes;
        }
        if (reg!=""){
            content = parse->get_num();
            this->reg_dict[reg]=content;
        }
        this->parse_result_list.emplace_back(parse);
    }
        string to_string() override{
        string str="";
        for (this->parse_result_iter = parse_result_list.begin();this->parse_result_iter!=parse_result_list.end(); this->parse_result_iter++){
            str += (**this->parse_result_iter).to_string();
        }
        return str;
    }
    cJSON * to_json_Option() override {
        cJSON * root;
        unsigned long tmp_num;
        root=cJSON_CreateObject();
        for (this->parse_result_iter = parse_result_list.begin();this->parse_result_iter!=parse_result_list.end(); this->parse_result_iter++){
                if((**this->parse_result_iter).tag=="Field"){
                    istringstream iss((**this->parse_result_iter).value);
                    iss>>tmp_num;
                    cJSON_AddNumberToObject(root,(**this->parse_result_iter).id.c_str(),tmp_num);
                } else{
                    cJSON_AddStringToObject(root,(**this->parse_result_iter).id.c_str(),(**this->parse_result_iter).value.c_str());

                }
        }
        return root;
    }
    void Switch_id2(){
        Field_parse("Field","MSS_length",1,0,0,1,"");
        Field_parse("Field","MSS_data",2,0,0,1,"");

}

    void Switch_id3(){
        Field_parse("Field","shift_length",1,0,0,1,"");
        Field_parse("Field","shift_count",1,0,0,1,"");

}

    void Switch_id4(){
        Field_parse("Field","SACK_length",1,0,0,1,"");

}

    void BlockArray_tcp_options(){
        int tmp_ptr = this->ptr;
        long length = (this->reg_dict["headerlength"]-5)*4;
        while (this->ptr < tmp_ptr+length){
            Field_parse("Field","kind",1,0,0,1,"kind");
            if (this->reg_dict["kind"]==0){break;}
            if(this->reg_dict["kind"]==2){Switch_id2();}
            if(this->reg_dict["kind"]==3){Switch_id3();}
            if(this->reg_dict["kind"]==4){Switch_id4();}

}
}
    void Parse(){
        BlockArray_tcp_options();}};


class test_xml : public Protocol{
private:
    char* data;
    int ptr=0;
public:
    test_xml(){}
    map<string,Protocol*> parse_result;
    vector<pair<string,Protocol*>> parse_vector;
    vector<pair<string,Protocol*>>::iterator iter_vector;
    test_xml(char* data,int ptr){
        this->type = "Protocol";
        this->data = data;
        this->ptr = ptr;
        this->Parse();
    }

    void Field_parse(string tag, string id, int bytes,int left,int right,int cursor,string reg){
        Field* parse = new Field(tag,id,&this->data[this->ptr],left,right,bytes);
        if (cursor!= 0){
            this->ptr +=bytes;
        }
        if (reg!=""){
            content = parse->get_num();
            this->reg_dict[reg]=content;
        }
        parse_result[id]=parse;
        parse_vector.emplace_back(make_pair(id,parse));
    }

    Protocol* get(string id){
        if(this->parse_result.count(id)>0){
            return this->parse_result[id];
        } else{
            return NULL;
        }
    };
    string to_string() override {
        string str="";
        for(iter_vector =parse_vector.begin();iter_vector!=parse_vector.end();iter_vector++){
            str+=iter_vector->second->to_string();
        }
        return str;
    };
    cJSON* to_json() override {
        cJSON *root;
        unsigned long tmp_num;
        root=cJSON_CreateObject();
        for (iter_vector =parse_vector.begin();iter_vector!=parse_vector.end();iter_vector++){
            if(iter_vector->second->type=="Field"){
             if(iter_vector->second->tag=="Field"){
                    istringstream iss(iter_vector->second->value);
                    iss>>tmp_num;
                    cJSON_AddNumberToObject(root,iter_vector->first.c_str(),tmp_num);
                } else{
                    cJSON_AddStringToObject(root,iter_vector->first.c_str(),iter_vector->second->value.c_str());

                }
            }
            else if(iter_vector->second->type=="Option"){
                cJSON_AddItemToObject(root,iter_vector->first.c_str(),iter_vector->second->to_json_Option());
            }
        }
        return root;
    }
    void Parse(){

    Field_parse("IP4", "test_ip4", 4, 0, 0, 1, "");
    Field_parse("IP6", "test_ip6", 16, 0, 0, 1, "");
    Field_parse("Mac", "test_mac", 6, 0, 0, 1, "");
    Field_parse("Bytes", "test_bytes", 10, 0, 0, 1, "");
    Field_parse("Field","Source_Port",2,0,0,1,"");
    Field_parse("Field","Destination_Port",2,0,0,1,"");
    Field_parse("Field","Sequence_Number",4,0,0,1,"");
    Field_parse("Field","Acknowledgement_Number",4,0,0,1,"");
    Field_parse("Field","Data_offset",1,0,4,0,"headerlength");
    Field_parse("Field","Reserved",1,4,7,0,"");
    Field_parse("Field","NS",1,7,8,1,"");
    Field_parse("Field","CWR",1,0,1,0,"");
    Field_parse("Field","ECE",1,1,2,0,"");
    Field_parse("Field","URG",1,2,3,0,"flag_URG");
    Field_parse("Field","ACK",1,3,4,0,"");
    Field_parse("Field","PSH",1,4,5,0,"");
    Field_parse("Field","RST",1,5,6,0,"");
    Field_parse("Field","SYN",1,6,7,0,"");
    Field_parse("Field","FIN",1,7,8,1,"");
    Field_parse("Field","Window_Size",2,0,0,1,"");
    Field_parse("Field","Checksum",2,0,0,1,"");
    Field_parse("Field","urgent_ptr",2,0,0,1,"");
    
    Option_TCP_option* option_TCP_option=new Option_TCP_option(&this->data[0],this->ptr,this->reg_dict);
    this->parse_result["TCP_option"]=option_TCP_option;                
    parse_vector.emplace_back(make_pair("TCP_option",option_TCP_option));
    this->reg_dict = option_TCP_option->get_reg_dict();
    this->ptr = option_TCP_option->get_ptr(); };

};