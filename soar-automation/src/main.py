#!/usr/bin/env python3
"""
SOAR Automation Main Application
Enterprise Banking SOC - Security Orchestration, Automation and Response
"""

import asyncio
import logging
import signal
import sys

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_settings
from core.logging_config import setup_logging
from services.orchestration_engine import OrchestrationEngine
from services.action_executor import ActionExecutor
from services.feedback_loop import FeedbackLoopService
from services.audit_logger import AuditLogger
from services.incident_manager import IncidentManager
from api.routes import router
from monitoring.metrics import setup_metrics

setup_logging()
logger = logging.getLogger(__name__)

# Global service instances
orchestration_engine = None
action_executor = None
feedback_service = None
audit_logger = None
incident_manager = None

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    settings = get_settings()
    
    app = FastAPI(
        title="Banking SOC SOAR Automation",
        description="Security Orchestration, Automation and Response Platform",
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
    
    app.include_router(router, prefix="/api/v1")
    setup_metrics(app)
    
    return app

async def initialize_services():
    """Initialize all SOAR services"""
    global orchestration_engine, action_executor, feedback_service, audit_logger, incident_manager
    
    logger.info("🚀 Initializing SOAR Automation services...")
    
    try:
        settings = get_settings()
        
        # Initialize audit logger first
        audit_logger = AuditLogger(settings)
        await audit_logger.initialize()
        logger.info("✅ Audit Logger initialized")
        
        # Initialize action executor
        action_executor = ActionExecutor(settings, audit_logger)
        await action_executor.initialize()
        logger.info("✅ Action Executor initialized")
        
        # Initialize incident manager
        incident_manager = IncidentManager(settings)
        await incident_manager.initialize()
        logger.info("✅ Incident Manager initialized")
        
        # Initialize orchestration engine
        orchestration_engine = OrchestrationEngine(settings, action_executor, incident_manager, audit_logger)
        await orchestration_engine.initialize()
        logger.info("✅ Orchestration Engine initialized")
        
        # Initialize feedback loop
        feedback_service = FeedbackLoopService(settings)
        await feedback_service.initialize()
        logger.info("✅ Feedback Loop Service initialized")
        
        logger.info("🎯 All SOAR services initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize services: {e}")
        raise

async def start_background_tasks():
    """Start background processing tasks"""
    logger.info("🔄 Starting background tasks...")
    
    tasks = [
        asyncio.create_task(orchestration_engine.start_processing()),
        asyncio.create_task(incident_manager.monitor_incidents()),
        asyncio.create_task(feedback_service.process_feedback()),
        asyncio.create_task(action_executor.cleanup_old_actions())
    ]
    
    return tasks

async def shutdown_services():
    """Gracefully shutdown all services"""
    logger.info("🛑 Shutting down SOAR services...")
    
    services = [orchestration_engine, action_executor, feedback_service, audit_logger, incident_manager]
    
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
    logger.info("🏦 Starting Banking SOC SOAR Automation Platform")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await initialize_services()
        app = create_app()
        background_tasks = await start_background_tasks()
        
        settings = get_settings()
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=settings.api_port,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config)
        
        logger.info(f"🌐 SOAR API server starting on port {settings.api_port}")
        
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
    asyncio.run(main())