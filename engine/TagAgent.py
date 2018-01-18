#
#   A Tag Agent is built to keeps all the tags that a applicable to this language
#

from tag.Tag import Tag

class TagAgent:

    def __init__(self,lang):
        self.tagmap=dict()
        self.lang=lang

    def __add__(self, tagType):

        assert issubclass(tagType,Tag) and self.lang==tagType.lang
        k = tagType.type
        self.tagmap[k]=tagType
        return self

    def getTag(self,name):

        if name in self.tagmap:
            return self.tagmap[name]
        else:
            raise IOError("this tag is not leagal: "+name)




