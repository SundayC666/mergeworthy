"""
Configuration settings using Pydantic
Loads environment variables from .env file
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",  # Ignore extra fields in .env file
    )

    # Server configuration
    # Listen on loopback by default: this is a single-user local tool. Set HOST=0.0.0.0
    # in .env only when the app must be reachable from other machines (e.g. in a container).
    HOST: str = Field(default="127.0.0.1", description="Server host")
    PORT: int = Field(default=8000, description="Server port")
    DEBUG: bool = Field(default=False, description="Debug mode")

    # Ollama configuration
    OLLAMA_HOST: str = Field(default="http://localhost:11434", description="Ollama server URL")
    OLLAMA_MODEL: str = Field(default="llama3.2:3b-instruct-q4_K_M", description="LLM model name")

    # Data configuration
    CVE_CACHE_FILE: str = Field(default="data/cve_cache.json", description="CVE cache file path")
    CVE_CACHE_TTL_HOURS: int = Field(default=6, description="CVE cache time-to-live in hours")
    CVE_LOOKBACK_DAYS: int = Field(default=30, description="Number of days to fetch CVEs")
    CVE_MAX_RESULTS: int = Field(default=50, description="Maximum number of CVEs to fetch")

    # API configuration
    NVD_API_KEY: str | None = Field(default=None, description="NIST NVD API key (optional)")

    @property
    def SERVER_URL(self) -> str:
        """Get the server URL"""
        # The literal is only compared against, never bound to (B104 is a false positive here).
        host = "localhost" if self.HOST == "0.0.0.0" else self.HOST  # nosec B104
        return f"http://{host}:{self.PORT}"


# Global settings instance
settings = Settings()
