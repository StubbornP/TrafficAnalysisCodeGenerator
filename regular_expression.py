import re

pat = re.compile(r'\{\{([\w|\d]+)\}\}')


def PY_expression_trans(string):
    for p in pat.finditer(string):
        reg = p.groups()[0]
        string = string.replace('{{%s}}' % reg, 'self.reg_dict[\"%s\"]' % reg)
    return string

def CPP_expression_trans(string):
    for p in pat.finditer(string):
        reg = p.groups()[0]
        string = string.replace('{{%s}}' % reg, 'this->reg_dict[\"%s\"]' % reg)
    return string

def JAVA_expression_trans(string):
    for p in pat.finditer(string):
        reg = p.groups()[0]
        string = string.replace('{{%s}}' % reg, 'this.reg_dict.get(\"%s\")' % reg)
    return string

def java_size_trans(s):
    for p in pat.finditer(s):
        reg = p.groups()[0]
        s = s.replace('{{%s}}' % reg, 'this.reg_dict.get(\"%s\")' % reg)
    return s


if __name__ == "__main__":
    string = "{{regname}}*4"
    print(java_size_trans(string))

