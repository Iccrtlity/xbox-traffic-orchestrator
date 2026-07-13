#!/bin/bash
cd /home/j/xbox-traffic-orchestrator
git pull
docker compose down
docker compose up -d --build