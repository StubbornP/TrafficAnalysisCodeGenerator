#
#   CodeGenerator process xml parse and code generate
#

from engine.TagSequence import  TagSequence

class CodeGenerator:

    def __init__(self,xml,tagAgent):
        self.xml=xml
        self.tagAgent=tagAgent
        self.tagSeq=None
        #...

    def parseXML(self):
        self.tagSeq=TagSequence()
        # process all tag and add to tag seq

    def generateCode(self):
        assert self.tagSeq is not None and len(self.tagSeq)>0,"tagSeq is empty..."
        code = ""
        for t in self.tagSeq:
            code += t()
        return code