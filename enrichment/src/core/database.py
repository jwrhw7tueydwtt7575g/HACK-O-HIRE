#!/usr/bin/env python3
"""Database clients for OpenSearch, Redis, Neo4j"""

import logging
from typing import Dict, List, Optional, Any
import asyncio

from opensearchpy import AsyncOpenSearch, OpenSearch
from opensearchpy.helpers import async_bulk, async_scan
import redis.asyncio as aioredis
from neo4j import AsyncGraphDatabase

logger = logging.getLogger(__name__)


class OpenSearchClient:
    """Async OpenSearch client wrapper"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client: Optional[AsyncOpenSearch] = None
        
    async def connect(self):
        """Establish connection to OpenSearch"""
        try:
            self.client = AsyncOpenSearch(
                hosts=self.config.get('hosts', ['http://opensearch:9200']),
                http_auth=(
                    self.config.get('username', 'admin'),
                    self.config.get('password', 'admin')
                ),
                use_ssl=self.config.get('use_ssl', False),
                verify_certs=self.config.get('verify_certs', False),
                ssl_show_warn=self.config.get('ssl_show_warn', False),
                timeout=self.config.get('timeout', 30),
                max_retries=self.config.get('max_retries', 3),
                retry_on_timeout=True
            )
            
            # Test connection
            info = await self.client.info()
            logger.info(f"✅ Connected to OpenSearch: {info['version']['number']}")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to OpenSearch: {e}")
            raise
    
    async def search(self, index: str, query: Dict, size: int = 100) -> List[Dict]:
        """Search documents"""
        try:
            response = await self.client.search(
                index=index,
                body=query,
                size=size
            )
            return [hit['_source'] for hit in response['hits']['hits']]
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    async def index_document(self, index: str, document: Dict, doc_id: Optional[str] = None):
        """Index a single document"""
        try:
            await self.client.index(
                index=index,
                body=document,
                id=doc_id,
                refresh=True
            )
        except Exception as e:
            logger.error(f"Failed to index document: {e}")
            raise
    
    async def bulk_index(self, index: str, documents: List[Dict]):
        """Bulk index documents"""
        try:
            actions = [
                {
                    '_index': index,
                    '_source': doc
                }
                for doc in documents
            ]
            
            success, failed = await async_bulk(self.client, actions)
            logger.info(f"Bulk indexed: {success} success, {failed} failed")
            
        except Exception as e:
            logger.error(f"Bulk index failed: {e}")
            raise
    
    async def get_document(self, index: str, doc_id: str) -> Optional[Dict]:
        """Get document by ID"""
        try:
            response = await self.client.get(index=index, id=doc_id)
            return response['_source']
        except Exception as e:
            logger.warning(f"Document not found: {e}")
            return None
    
    async def scroll_search(self, index: str, query: Dict, scroll_size: int = 1000):
        """Scroll through large result sets"""
        try:
            async for doc in async_scan(
                client=self.client,
                index=index,
                query=query,
                size=scroll_size
            ):
                yield doc['_source']
        except Exception as e:
            logger.error(f"Scroll search failed: {e}")
    
    async def update_document(self, index: str, doc_id: str, updates: Dict):
        """Update document"""
        try:
            await self.client.update(
                index=index,
                id=doc_id,
                body={'doc': updates},
                refresh=True
            )
        except Exception as e:
            logger.error(f"Update failed: {e}")
            raise
    
    async def close(self):
        """Close connection"""
        if self.client:
            await self.client.close()
            logger.info("OpenSearch connection closed")


class RedisClient:
    """Async Redis client wrapper"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client: Optional[aioredis.Redis] = None
        
    async def connect(self):
        """Establish connection to Redis"""
        try:
            self.client = await aioredis.from_url(
                self.config.get('url', 'redis://redis:6379/0'),
                encoding="utf-8",
                decode_responses=True,
                max_connections=self.config.get('max_connections', 50)
            )
            
            # Test connection
            await self.client.ping()
            logger.info("✅ Connected to Redis")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to Redis: {e}")
            raise
    
    async def get(self, key: str) -> Optional[str]:
        """Get value by key"""
        try:
            return await self.client.get(key)
        except Exception as e:
            logger.error(f"Redis GET failed: {e}")
            return None
    
    async def set(self, key: str, value: str, expiry: Optional[int] = None):
        """Set key-value pair"""
        try:
            await self.client.set(key, value, ex=expiry)
        except Exception as e:
            logger.error(f"Redis SET failed: {e}")
    
    async def delete(self, key: str):
        """Delete key"""
        try:
            await self.client.delete(key)
        except Exception as e:
            logger.error(f"Redis DELETE failed: {e}")
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            return await self.client.exists(key) > 0
        except Exception as e:
            logger.error(f"Redis EXISTS failed: {e}")
            return False
    
    async def close(self):
        """Close connection"""
        if self.client:
            await self.client.close()
            logger.info("Redis connection closed")


class Neo4jClient:
    """Async Neo4j client wrapper for graph analytics"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.driver = None
        
    async def connect(self):
        """Establish connection to Neo4j"""
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.config.get('uri', 'bolt://neo4j:7687'),
                auth=(
                    self.config.get('username', 'neo4j'),
                    self.config.get('password', 'password')
                ),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=120
            )
            
            # Verify connectivity
            await self.driver.verify_connectivity()
            logger.info("✅ Connected to Neo4j")
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to Neo4j: {e}")
            raise
    
    async def execute_query(self, query: str, parameters: Optional[Dict] = None) -> List[Dict]:
        """Execute Cypher query"""
        try:
            async with self.driver.session() as session:
                result = await session.run(query, parameters or {})
                records = await result.data()
                return records
        except Exception as e:
            logger.error(f"Neo4j query failed: {e}")
            return []
    
    async def create_node(self, label: str, properties: Dict):
        """Create a node"""
        query = f"CREATE (n:{label} $props) RETURN n"
        return await self.execute_query(query, {'props': properties})
    
    async def create_relationship(self, from_id: str, to_id: str, rel_type: str, properties: Optional[Dict] = None):
        """Create relationship between nodes"""
        query = f"""
        MATCH (a), (b)
        WHERE a.id = $from_id AND b.id = $to_id
        CREATE (a)-[r:{rel_type} $props]->(b)
        RETURN r
        """
        return await self.execute_query(query, {
            'from_id': from_id,
            'to_id': to_id,
            'props': properties or {}
        })
    
    async def find_attack_path(self, start_node: str, end_node: str) -> List[List[str]]:
        """Find attack paths between nodes"""
        query = """
        MATCH path = shortestPath(
            (start {id: $start_id})-[*]-(end {id: $end_id})
        )
        RETURN [node in nodes(path) | node.id] as path
        LIMIT 10
        """
        results = await self.execute_query(query, {
            'start_id': start_node,
            'end_id': end_node
        })
        return [r['path'] for r in results]
    
    async def close(self):
        """Close connection"""
        if self.driver:
            await self.driver.close()
            logger.info("Neo4j connection closed")
