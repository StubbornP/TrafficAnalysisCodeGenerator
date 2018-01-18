#
#   This is the root class of tag.so a tag implementation must have a specified *tag type*
#   and the language it process
#   Call the tag to generate code
#

class Tag:

    type="Not implemented"
    lang="Not implemented"

    def __init__(self,xmlObject):
        pass

    def __call__(self, *args, **kwargs):
        assert False,"Tag is abstract, so it`s not callable."

    def getType(self):
        assert issubclass(type(self), Tag),"Getting type of a non-Tag object?"
        return  type(self).type

    def getLang(self):
        assert issubclass(type(self), Tag),"Getting lang of a non-Tag object?"
        return type(self).lang