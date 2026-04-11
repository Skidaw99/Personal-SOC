from collectors.meta import MetaCollector
from collectors.twitter import TwitterCollector
from collectors.youtube import YouTubeCollector

COLLECTOR_REGISTRY = {
    "facebook": MetaCollector(),
    "instagram": MetaCollector(),
    "twitter": TwitterCollector(),
    "youtube": YouTubeCollector(),
}

__all__ = [
    "MetaCollector", "TwitterCollector",
    "YouTubeCollector", "COLLECTOR_REGISTRY",
]
