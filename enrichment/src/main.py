#!/usr/bin/env python3
"""
Enrichment Service Main Application
Enterprise Banking SOC - Threat Intelligence and LLM Playbook Generation
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_settings
from services.intelligence_enrichment import IntelligenceEnrichmentService
from services.llm_playbook import LLMPlaybookService

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global service instances
intelligence_service = None
llm_service = None

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    settings = get_settings()
    
    app = FastAPI(
        title="Banking SOC Enrichment & LLM Service",
        description="Threat Intelligence Enrichment and Automated Playbook Generation",
        version="1.0.0",
        docs_url="/api/docs" if settings.environment == "development" else None,
        redoc_url="/api/redoc" if settings.environment == "development" else None
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "https://banking-soc.internal"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # app.include_router(router, prefix="/api/v1")
    # setup_metrics(app)
    
    return app

async def initialize_services():
    """Initialize all enrichment services"""
    global intelligence_service, llm_service
    
    logger.info("🚀 Initializing Enrichment services...")
    
    try:
        settings = get_settings()
        
        # Initialize Intelligence Enrichment (CVE/NVD, CISA KEV, Threat Intel, Asset)
        intelligence_service = IntelligenceEnrichmentService(settings)
        await intelligence_service.initialize()
        logger.info("✅ Intelligence Enrichment Service initialized")
        
        # Initialize LLM playbook generation
        llm_service = LLMPlaybookService(settings)
        await llm_service.initialize()
        logger.info("✅ LLM Playbook Service initialized")
        
        logger.info("🎯 All Enrichment services initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize services: {e}")
        raise

async def start_background_tasks():
    """Start background processing tasks"""
    logger.info("🔄 Starting background tasks...")
    
    # Start incident polling and processing loop
    asyncio.create_task(process_incidents_loop())

async def process_incidents_loop():
    """Main processing loop for enrichment and playbook generation"""
    from core.database import OpenSearchClient
    from models.incident import EnrichedIncident, IncidentStatus
    
    settings = get_settings()
    opensearch = OpenSearchClient(settings.opensearch.model_dump())
    await opensearch.connect()
    
    logger.info("Starting incident processing loop...")
    
    while True:
        try:
            # Query for new incidents from OpenSearch
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"status": "new"}},
                            {"term": {"source": "wazuh"}}
                        ]
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            incidents_data = await opensearch.search(
                index="banking-soc-incidents",
                query=query,
                size=settings.batch_size
            )
            
            if incidents_data:
                logger.info(f"Processing {len(incidents_data)} new incidents")
                
                for incident_data in incidents_data:
                    try:
                        # Parse incident
                        incident = EnrichedIncident(**incident_data)
                        
                        # Enrich with intelligence
                        incident.status = IncidentStatus.ENRICHING
                        await opensearch.update_document(
                            "banking-soc-incidents",
                            incident.incident_id,
                            {"status": incident.status}
                        )
                        
                        enriched_incident = await intelligence_service.enrich_incident(incident)
                        enriched_incident.status = IncidentStatus.ENRICHED
                        
                        # Save enriched incident
                        await opensearch.index_document(
                            "banking-soc-incidents-enriched",
                            enriched_incident.incident_id,
                            enriched_incident.model_dump()
                        )
                        
                        # Generate playbook
                        enriched_incident.status = IncidentStatus.ANALYZING
                        playbook = await llm_service.generate_playbook(enriched_incident)
                        
                        # Save playbook
                        await opensearch.index_document(
                            "banking-soc-playbooks",
                            playbook.model_dump(),
                            doc_id=playbook.incident_id
                        )
                        
                        # Mark incident as processed
                        await opensearch.update_document(
                            "banking-soc-incidents",
                            incident.incident_id,
                            {"status": "enriched_and_analyzed", "enriched_at": datetime.now().isoformat()}
                        )
                        
                        logger.info(f"✅ Processed incident {incident.incident_id}")
                        
                    except Exception as e:
                        logger.error(f"Failed to process incident: {e}")
                        continue
            
            # Wait before next poll
            await asyncio.sleep(settings.incident_poll_interval_seconds)
            
        except Exception as e:
            logger.error(f"Error in processing loop: {e}")
            await asyncio.sleep(60)

async def shutdown_services():
    """Gracefully shutdown all services"""
    logger.info("🛑 Shutting down Enrichment services...")
    
    services = [intelligence_service, llm_service]
    
    for service in services:
        if service:
            try:
                await service.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down service: {e}")
    
    logger.info("✅ Services shutdown complete")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    asyncio.create_task(shutdown_services())
    sys.exit(0)

async def main():
    """Main application entry point"""
    logger.info("🏦 Starting Banking SOC Enrichment & LLM Service")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await initialize_services()
        app = create_app()
        await start_background_tasks()
        
        settings = get_settings()
        config = uvicorn.Config(
            app,
            host=settings.host,
            port=settings.port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)
        
        logger.info(f"🌐 Enrichment API server starting on {settings.host}:{settings.port}")
        
        await server.serve()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        raise
    finally:
        await shutdown_services()

if __name__ == "__main__":
    asyncio.run(main())