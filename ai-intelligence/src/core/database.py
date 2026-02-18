#!/usr/bin/env python3
"""Database clients for AI Intelligence Service - OpenSearch, Redis, Neo4j"""

import logging
from typing import Dict, List, Optional, Any
import asyncio
import json

from opensearchpy import AsyncOpenSearch
from opensearchpy.helpers import async_bulk, async_scan
import redis.asyncio as aioredis
from neo4j import AsyncGraphDatabase

logger = logging.getLogger("ai-intelligence")


class OpenSearchClient:
    """Async OpenSearch client for event queries and incident indexing"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None

    async def connect(self):
        """Initialize OpenSearch connection"""
        self.client = AsyncOpenSearch(
            hosts=self.config.get("hosts", ["http://opensearch:9200"]),
            http_auth=(
                self.config.get("username", "admin"),
                self.config.get("password", "admin")
            ),
            use_ssl=self.config.get("use_ssl", False),
            verify_certs=self.config.get("verify_certs", False),
            ssl_show_warn=False,
        )
        logger.info("OpenSearch client connected")

    async def search(self, index: str, query: Dict, size: int = 100) -> List[Dict]:
        """Execute search query and return hits"""
        try:
            response = await self.client.search(
                index=index, body=query, size=size
            )
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"OpenSearch search failed: {e}")
            return []

    async def scroll_search(self, index: str, query: Dict, scroll: str = "5m") -> List[Dict]:
        """Execute scroll search for large result sets"""
        results = []
        try:
            async for hit in async_scan(
                self.client, index=index, query=query, scroll=scroll
            ):
                results.append(hit["_source"])
        except Exception as e:
            logger.error(f"OpenSearch scroll search failed: {e}")
        return results

    async def index_document(self, index: str, doc_id: str, document: Dict):
        """Index a single document"""
        try:
            await self.client.index(index=index, id=doc_id, body=document)
        except Exception as e:
            logger.error(f"OpenSearch index failed: {e}")

    async def bulk_index(self, index: str, documents: List[Dict]):
        """Bulk index documents"""
        actions = [
            {"_index": index, "_source": doc}
            for doc in documents
        ]
        try:
            await async_bulk(self.client, actions)
            logger.info(f"Bulk indexed {len(documents)} documents to {index}")
        except Exception as e:
            logger.error(f"OpenSearch bulk index failed: {e}")

    async def close(self):
        if self.client:
            await self.client.close()


class RedisClient:
    """Async Redis client for caching baselines and model state"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None

    async def connect(self):
        """Initialize Redis connection"""
        self.client = aioredis.Redis(
            host=self.config.get("host", "redis"),
            port=self.config.get("port", 6379),
            password=self.config.get("password", None) or None,
            db=self.config.get("db", 1),
            decode_responses=True,
        )
        logger.info("Redis client connected")

    async def get_json(self, key: str) -> Optional[Dict]:
        """Get and parse JSON value"""
        try:
            value = await self.client.get(key)
            return json.loads(value) if value else None
        except Exception as e:
            logger.error(f"Redis get failed for key {key}: {e}")
            return None

    async def set_json(self, key: str, value: Dict, ttl: int = 3600):
        """Store JSON value with TTL"""
        try:
            await self.client.setex(key, ttl, json.dumps(value))
        except Exception as e:
            logger.error(f"Redis set failed for key {key}: {e}")

    async def get_hash(self, key: str) -> Optional[Dict]:
        """Get full hash"""
        try:
            return await self.client.hgetall(key)
        except Exception as e:
            logger.error(f"Redis hgetall failed for key {key}: {e}")
            return None

    async def set_hash(self, key: str, mapping: Dict, ttl: int = 3600):
        """Set hash with TTL"""
        try:
            await self.client.hset(key, mapping=mapping)
            await self.client.expire(key, ttl)
        except Exception as e:
            logger.error(f"Redis hset failed for key {key}: {e}")

    async def close(self):
        if self.client:
            await self.client.close()


class Neo4jClient:
    """Async Neo4j client for attack chain reconstruction and entity graphs"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.driver = None

    async def connect(self):
        """Initialize Neo4j driver"""
        self.driver = AsyncGraphDatabase.driver(
            self.config.get("uri", "bolt://neo4j:7687"),
            auth=(
                self.config.get("username", "neo4j"),
                self.config.get("password", "banking_neo4j_2024")
            ),
        )
        logger.info("Neo4j driver connected")

    async def run_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """Execute a Cypher query and return results as list of dicts"""
        results = []
        try:
            async with self.driver.session() as session:
                result = await session.run(query, parameters or {})
                records = await result.data()
                results = records
        except Exception as e:
            logger.error(f"Neo4j query failed: {e}")
        return results

    async def create_node(self, label: str, properties: Dict):
        """Create a node with given label and properties"""
        query = f"CREATE (n:{label} $props) RETURN n"
        return await self.run_query(query, {"props": properties})

    async def create_relationship(self, from_id: str, to_id: str,
                                   rel_type: str, properties: Dict = None):
        """Create a relationship between two nodes"""
        query = f"""
        MATCH (a {{id: $from_id}}), (b {{id: $to_id}})
        CREATE (a)-[r:{rel_type} $props]->(b)
        RETURN r
        """
        return await self.run_query(query, {
            "from_id": from_id,
            "to_id": to_id,
            "props": properties or {}
        })

    async def get_attack_chain(self, entity_id: str, depth: int = 5) -> List[Dict]:
        """Traverse attack chain graph for an entity"""
        query = """
        MATCH path = (start {id: $entity_id})-[*1..""" + str(depth) + """]->(end)
        RETURN nodes(path) as nodes, relationships(path) as relationships
        ORDER BY length(path) DESC
        LIMIT 10
        """
        return await self.run_query(query, {"entity_id": entity_id})

    async def close(self):
        if self.driver:
            await self.driver.close()
