"""
CrawlBouncer — Start the server
Run this file to start CrawlBouncer:
    python run.py
"""
import uvicorn
from app.config import cfg

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=cfg.HOST,
        port=cfg.PORT,
        reload=cfg.is_development,
        log_level="info",
    )
