#
#   Helps to keep all supported tag
#

from engine.TagAgent import TagAgent
from tag.Tag import Tag
from tag.CPPTag import *
from tag.PYTag import *
from tag.JAVATag import *
class TagRegistry:

    tags=set()
    @staticmethod
    def Clear():
        TagRegistry.tags=set()

    @staticmethod
    def RegistTag(tag):
        assert issubclass(tag,Tag)
        TagRegistry.tags.add(tag)

    @staticmethod
    def buildTagAgent(lang):

        agent = TagAgent(lang)

        for tag in TagRegistry.tags:
            if tag.lang == lang:
                agent += tag
        return agent

    @staticmethod
    def __iter__(self):
        return TagRegistry.tags


def initTagRegistry():

    TagRegistry.Clear()

    TagRegistry.RegistTag(PYInitTag)
    TagRegistry.RegistTag(PYBlockArrayTag)
    TagRegistry.RegistTag(PYFieldTag)
    TagRegistry.RegistTag(PYContainerTag)
    TagRegistry.RegistTag(PYSwitchTag)
    TagRegistry.RegistTag(PYProtocolTag)
    TagRegistry.RegistTag(PYIP4Tag)
    TagRegistry.RegistTag(PYMacTag)
    TagRegistry.RegistTag(PYOptionTag)
    TagRegistry.RegistTag(PYIP6Tag)
    TagRegistry.RegistTag(PYPassTag)
    TagRegistry.RegistTag(PYBreakTag)
    TagRegistry.RegistTag(PYParseTag)
    TagRegistry.RegistTag(PYNopTag)
    TagRegistry.RegistTag(PYBytesTag)

    TagRegistry.RegistTag(JAVAInitTag)
    TagRegistry.RegistTag(JAVABlockArrayTag)
    TagRegistry.RegistTag(JAVAFieldTag)
    TagRegistry.RegistTag(JAVAContainerTag)
    TagRegistry.RegistTag(JAVASwitchTag)
    TagRegistry.RegistTag(JAVAProtocolTag)
    TagRegistry.RegistTag(JAVAIP4Tag)
    TagRegistry.RegistTag(JAVAMacTag)
    TagRegistry.RegistTag(JAVAOptionTag)
    TagRegistry.RegistTag(JAVAIP6Tag)
    TagRegistry.RegistTag(JAVAPassTag)
    TagRegistry.RegistTag(JAVABreakTag)
    TagRegistry.RegistTag(JAVAParseTag)
    TagRegistry.RegistTag(JAVANopTag)
    TagRegistry.RegistTag(JAVABytesTag)

    TagRegistry.RegistTag(CPPInitTag)
    TagRegistry.RegistTag(CPPBlockArrayTag)
    TagRegistry.RegistTag(CPPFieldTag)
    TagRegistry.RegistTag(CPPContainerTag)
    TagRegistry.RegistTag(CPPSwitchTag)
    TagRegistry.RegistTag(CPPProtocolTag)
    TagRegistry.RegistTag(CPPIP4Tag)
    TagRegistry.RegistTag(CPPMacTag)
    TagRegistry.RegistTag(CPPOptionTag)
    TagRegistry.RegistTag(CPPIP6Tag)
    TagRegistry.RegistTag(CPPPassTag)
    TagRegistry.RegistTag(CPPBreakTag)
    TagRegistry.RegistTag(CPPParseTag)
    TagRegistry.RegistTag(CPPNopTag)
    TagRegistry.RegistTag(CPPBytesTag)


    return TagRegistry

