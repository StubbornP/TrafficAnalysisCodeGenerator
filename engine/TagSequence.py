#
#   This class help to keep a tag sequence for a tag embedded tag.
#

from tag.Tag import Tag

class TagSequence:

    def __init__(self):
        self.tags = []

    def __add__(self, tag):
        assert issubclass(type(tag),Tag),"Argument tag must be a Tag object"
        self.tags.append(tag)
        return self

    def __iter__(self):
        for t in self.tags:
            yield t
