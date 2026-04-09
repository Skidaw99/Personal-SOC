from collectors.meta import MetaCollector
from collectors.twitter import TwitterCollector
from collectors.linkedin import LinkedInCollector
from collectors.tiktok import TikTokCollector
from collectors.youtube import YouTubeCollector

COLLECTOR_REGISTRY = {
    "facebook": MetaCollector(),
    "instagram": MetaCollector(),
    "twitter": TwitterCollector(),
    "linkedin": LinkedInCollector(),
    "tiktok": TikTokCollector(),
    "youtube": YouTubeCollector(),
}

__all__ = [
    "MetaCollector", "TwitterCollector", "LinkedInCollector",
    "TikTokCollector", "YouTubeCollector", "COLLECTOR_REGISTRY",
]
