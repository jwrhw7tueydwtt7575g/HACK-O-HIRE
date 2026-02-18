#!/usr/bin/env python3
"""
AI Intelligence UEBA Main Application
Enterprise Banking SOC - Behavioral Analytics and Anomaly Detection
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_settings
from core.logging_config import setup_logging
from services.ueba_service import UEBAService
from services.anomaly_detector import AnomalyDetectorService
from services.behavioral_modeler import BehavioralModelerService
from services.incident_processor import IncidentProcessorService
from api.routes import router
from monitoring.metrics import setup_metrics

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

# Global service instances
ueba_service = None
anomaly_service = None
behavioral_service = None
incident_service = None

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    settings = get_settings()
    
    app = FastAPI(
        title="Banking SOC AI Intelligence",
        description="User and Entity Behavior Analytics for Enterprise Banking Security",
        version="1.0.0",
        docs_url="/api/docs" if settings.environment == "development" else None,
        redoc_url="/api/redoc" if settings.environment == "development" else None
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "https://banking-soc.internal"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include API routes
    app.include_router(router, prefix="/api/v1")
    
    # Setup metrics
    setup_metrics(app)
    
    return app

async def initialize_services():
    """Initialize all AI Intelligence services"""
    global ueba_service, anomaly_service, behavioral_service, incident_service
    
    logger.info("🚀 Initializing AI Intelligence services...")
    
    try:
        settings = get_settings()
        
        # Initialize UEBA service
        ueba_service = UEBAService(settings)
        await ueba_service.initialize()
        logger.info("✅ UEBA Service initialized")
        
        # Initialize anomaly detector
        anomaly_service = AnomalyDetectorService(settings)
        await anomaly_service.initialize()
        logger.info("✅ Anomaly Detector Service initialized")
        
        # Initialize behavioral modeler
        behavioral_service = BehavioralModelerService(settings)
        await behavioral_service.initialize()
        logger.info("✅ Behavioral Modeler Service initialized")
        
        # Initialize incident processor
        incident_service = IncidentProcessorService(settings)
        await incident_service.initialize()
        logger.info("✅ Incident Processor Service initialized")
        
        logger.info("🎯 All AI Intelligence services initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize services: {e}")
        raise

async def start_background_tasks():
    """Start background processing tasks"""
    logger.info("🔄 Starting background tasks...")
    
    tasks = [
        asyncio.create_task(ueba_service.start_processing()),
        asyncio.create_task(anomaly_service.start_detection()),
        asyncio.create_task(behavioral_service.start_modeling()),
        asyncio.create_task(incident_service.start_processing())
    ]
    
    return tasks

async def shutdown_services():
    """Gracefully shutdown all services"""
    logger.info("🛑 Shutting down AI Intelligence services...")
    
    services = [ueba_service, anomaly_service, behavioral_service, incident_service]
    
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
    logger.info("🏦 Starting Banking SOC AI Intelligence System")
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize services
        await initialize_services()
        
        # Create FastAPI app
        app = create_app()
        
        # Start background tasks
        background_tasks = await start_background_tasks()
        
        # Get configuration
        settings = get_settings()
        
        # Start the API server
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=settings.api_port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)
        
        logger.info(f"🌐 AI Intelligence API server starting on port {settings.api_port}")
        
        # Run server and background tasks concurrently
        await asyncio.gather(
            server.serve(),
            *background_tasks,
            return_exceptions=True
        )
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        raise
    finally:
        await shutdown_services()

if __name__ == "__main__":
    # Run the application
    asyncio.run(main())