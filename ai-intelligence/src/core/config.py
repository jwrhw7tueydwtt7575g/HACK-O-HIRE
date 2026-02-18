#!/usr/bin/env python3
"""Configuration management for AI Intelligence Service"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from functools import lru_cache


class OpenSearchConfig(BaseModel):
    """OpenSearch connection configuration"""
    hosts: list = Field(default=["https://opensearch:9200"])
    username: str = Field(default="ai_intelligence_user")
    password: str = Field(default_factory=lambda: os.getenv("OPENSEARCH_AI_PASSWORD", "admin"))
    use_ssl: bool = True
    verify_certs: bool = False
    index_patterns: list = Field(default=["banking-soc-logs-*"])


class RedisConfig(BaseModel):
    """Redis connection configuration"""
    host: str = Field(default="redis")
    port: int = Field(default=6379)
    password: str = Field(default_factory=lambda: os.getenv("REDIS_PASSWORD", ""))
    db: int = Field(default=1)
    ttl_seconds: int = Field(default=3600)


class Neo4jConfig(BaseModel):
    """Neo4j connection configuration"""
    uri: str = Field(default="bolt://neo4j:7687")
    username: str = Field(default="neo4j")
    password: str = Field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", "banking_neo4j_2024"))


class MLConfig(BaseModel):
    """Machine learning model configuration"""
    isolation_forest: Dict[str, Any] = Field(default={
        "contamination": 0.1,
        "n_estimators": 100,
        "max_samples": "auto",
        "random_state": 42
    })
    autoencoder: Dict[str, Any] = Field(default={
        "encoding_dim": 32,
        "hidden_layers": [128, 64],
        "epochs": 50,
        "batch_size": 256,
        "learning_rate": 0.001,
        "reconstruction_threshold": 0.05
    })
    hbos: Dict[str, Any] = Field(default={
        "n_bins": 50,
        "alpha": 0.1,
        "contamination": 0.1
    })
    baseline_window_days: int = Field(default=30)
    retrain_interval_hours: int = Field(default=24)
    min_samples_for_training: int = Field(default=100)


class RiskScoringConfig(BaseModel):
    """Risk scoring weights configuration"""
    time_weight: float = Field(default=0.20)
    location_weight: float = Field(default=0.25)
    transaction_weight: float = Field(default=0.30)
    access_weight: float = Field(default=0.15)
    peer_weight: float = Field(default=0.10)


class ServiceConfig(BaseModel):
    """Service-level configuration"""
    name: str = Field(default="banking-soc-ai-intelligence")
    version: str = Field(default="1.0.0")
    environment: str = Field(default="production")
    api_port: int = Field(default=8000)
    metrics_port: int = Field(default=9090)
    log_level: str = Field(default="INFO")


class Settings(BaseModel):
    """Root settings for AI Intelligence Service"""
    service: ServiceConfig = Field(default_factory=ServiceConfig)
    opensearch: OpenSearchConfig = Field(default_factory=OpenSearchConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)

    @classmethod
    def from_yaml(cls, config_path: str) -> "Settings":
        """Load settings from YAML configuration file"""
        path = Path(config_path)
        if path.exists():
            with open(path, 'r') as f:
                config_data = yaml.safe_load(f)
            return cls(**config_data)
        return cls()


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    config_path = os.getenv(
        "AI_INTELLIGENCE_CONFIG",
        "/app/config/ai-intelligence.yaml"
    )
    return Settings.from_yaml(config_path)
