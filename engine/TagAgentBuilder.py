#
#   build a TagAgent of a specified language.
#

from tag.TagRegistry import TagRegistry

def buildTagAgent(lang):

    agent =TagRegistry.buildTagAgent(lang)
    return agent



