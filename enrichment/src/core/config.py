#!/usr/bin/env python3
"""Configuration management for Enrichment Layer"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class OpenSearchConfig(BaseModel):
    """OpenSearch connection configuration"""
    hosts: list = Field(default=["https://opensearch:9200"])
    username: str = Field(default="admin")
    password: str = Field(default_factory=lambda: os.getenv("OPENSEARCH_PASSWORD", "admin"))
    use_ssl: bool = True
    verify_certs: bool = False
    ssl_show_warn: bool = False
    timeout: int = 30
    max_retries: int = 3


class LLMConfig(BaseModel):
    """LLM configuration"""
    mode: str = Field(default="cloud")  # cloud, on_premises, hybrid
    local_model: Optional[str] = "meta-llama/Llama-2-13b-chat-hf"
    openai_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    anthropic_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    max_tokens: int = 2000
    temperature: float = 0.3
    model_cache_dir: str = "/models"


class CVEConfig(BaseModel):
    """CVE/NVD configuration"""
    nvd_api_key: Optional[str] = Field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cache_ttl_hours: int = 24
    rate_limit_per_minute: int = 50


class ThreatIntelConfig(BaseModel):
    """Threat Intelligence configuration"""
    feeds: Dict[str, str] = Field(default_factory=lambda: {
        "abuse_ch": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "emergingthreats": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "alienvault": "https://reputation.alienvault.com/reputation.generic"
    })
    update_interval_hours: int = 6
    ioc_retention_days: int = 90


class AssetConfig(BaseModel):
    """Asset criticality configuration"""
    asset_db_path: str = "/config/assets.json"
    default_criticality: int = 5
    business_unit_mapping: Dict[str, int] = Field(default_factory=lambda: {
        "core_banking": 10,
        "trading": 10,
        "payments": 9,
        "customer_portal": 8,
        "internal_apps": 6,
        "development": 4,
        "test": 2
    })


class Settings(BaseModel):
    """Main application settings"""
    app_name: str = "Enterprise Banking Intelligence Enrichment Layer"
    version: str = "1.0.0"
    environment: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "production"))
    log_level: str = Field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    
    # Service configuration
    host: str = "0.0.0.0"
    port: int = 8002
    workers: int = 4
    
    # Component configurations
    opensearch: OpenSearchConfig = Field(default_factory=OpenSearchConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    cve: CVEConfig = Field(default_factory=CVEConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    asset: AssetConfig = Field(default_factory=AssetConfig)
    
    # Directories
    config_dir: str = "/config"
    prompts_dir: str = "/prompts"
    cache_dir: str = "/cache"
    
    # Processing configuration
    incident_poll_interval_seconds: int = 30
    batch_size: int = 10
    max_concurrent_enrichments: int = 5
    
    # Integration endpoints
    soar_url: str = Field(default_factory=lambda: os.getenv("SOAR_URL", "http://soar:8003"))
    wazuh_api_url: str = Field(default_factory=lambda: os.getenv("WAZUH_API_URL", "https://wazuh:55000"))
    
    @classmethod
    def load_from_file(cls, config_path: str = "/config/enrichment.yaml") -> "Settings":
        """Load settings from YAML file"""
        config_file = Path(config_path)
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
                return cls(**config_data)
        
        # Return defaults if file doesn't exist
        return cls()
    
    def to_yaml(self, output_path: str):
        """Export settings to YAML file"""
        with open(output_path, 'w') as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)


# Global settings instance
settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create settings instance"""
    global settings
    if settings is None:
        settings = Settings.load_from_file()
    return settings
